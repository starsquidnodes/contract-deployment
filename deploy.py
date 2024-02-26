#!/usr/bin/env python3

import argparse
import subprocess
import os
import hashlib
import json
import yaml
import logging
import sys
import glob
import requests
from mako.template import Template
import base64
import time


class Class:
    def __init__(self, d):
        for k, v in d.items():
            if isinstance(v, dict):
                v = Class(v)
            setattr(self, k, v)


class Contract():
    code = None
    label = None
    msg = None
    funds = None

    def __init__(self, definition):
        for k, v in definition.items():
            setattr(self, k, v)


class Code:
    def __init__(self, source):
        self.hash = None
        self.code = None
        self.source = source


class Deployer:
    def __init__(self, binary, chain_id, wallet, sources=[]):
        info("init deployer", binary=binary, chain_id=chain_id)

        self.binary = binary
        self.chain_id = chain_id
        self.wallet = wallet

        self.home = os.path.expanduser("~/.pond/kujira1-1")
        self.tmpdir = "/tmp"

        self.api_url = "https://api-kujira.starsquid.io"

        self.codes = self.__set_codes(sources)

        # map of all available code ids deployed in $chain_id
        # {data_hash: code_id}
        self.code_ids = {}
        self.update_code_ids()

        self.address = "kujira1k3g54c2sc7g9mgzuzaukm9pvuzcjqy92nk9wse"

        self.denoms = {}
        self.contracts = []

    def __set_codes(self, sources):
        codes = {}

        code_ids = yaml.safe_load(open("./code_ids.yml", "r").read())
        for name, id in code_ids.items():
            codes[name] = Code(f"{self.api_url}/cosmwasm/wasm/v1/code/{id}")

        if not os.path.isdir("./wasm"):
            error("./wasm not found")

        sources = glob.glob("./wasm/*.wasm") + sources

        for source in sources:
            name = os.path.basename(source).replace(".wasm", "")
            codes[name] = Code(source)

        return codes

    def handle_code(self, name):
        info("handle code", name=name)
        code = self.codes.get(name)
        if not code:
            error("code not found", name=name)

        code_hash = code.hash

        if not code_hash:
            info("code hash missing")
            if code.source.startswith("https://"):
                info("download code from mainnet", url=code.source)
                response = requests.get(code.source)

                response.raise_for_status()

                data = response.json()

                code_hash = data["code_info"]["data_hash"]

                filename = f"{self.tmpdir}/{name}.wasm"
                open(filename, "wb").write(
                    base64.b64decode(data["data"])
                )
                self.codes[name].hash = code_hash
                self.codes[name].source = filename

                code_id = self.code_ids.get(code_hash)
                if code_id:
                    info("code already deployed", code_id=code_id)
                    self.codes[name].id = code_id
                    return

                self.deploy_code(name)

        return code_hash

    def deploy_code(self, name):
        info("deploy code", name=name)
        code = self.codes[name]

        self.tx(f"wasm store {code.source}")
        self.code_ids[code.hash] = str(len(self.code_ids) + 1)

    def update_code_ids(self):
        code_infos = []
        next_key = "dummy"

        while next_key:
            result = self.q("wasm list-code")
            code_infos += result["code_infos"]
            next_key = result["pagination"]["next_key"]

        for info in code_infos:
            self.code_ids[info["data_hash"]] = info["code_id"]

    def q(self, args, extra=True, parse_json=True, ignore_errors=False):
        command = [
            self.binary, "--home", self.home, "query"
        ] + args.split()

        if extra:
            command += [
                "--node", "http://127.0.0.1:10157",
                "--chain-id", self.chain_id, "--output", "json",
            ]

        debug(" ".join(command))

        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode == 0:
            if not parse_json:
                return result.stdout.strip()

            return json.loads(result.stdout)
        else:
            if ignore_errors:
                return None
            error(result.stderr)

    def tx(self, args, ignore_errors=False):
        if isinstance(args, str):
            args = args.split()

        command = [
            self.binary, "--home", self.home, "tx"
        ] + args + [
            "--node", "http://127.0.0.1:10157",
            "--chain-id", self.chain_id, "--output", "json",
            "--from", self.wallet, "--keyring-backend", "test",
            "--gas", "auto", "--gas-adjustment", "2", "--yes",
        ]

        debug("send transaction", command=" ".join(command))

        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode != 0:
            if ignore_errors:
                return None
            else:
                error(result.stderr)

        result = json.loads(result.stdout)
        debug(None, result=result)
        txhash = result.get("txhash")
        if txhash:
            self.wait_for(txhash)

        return result

    def wait_for(self, txhash):
        info("wait for tx", tx=txhash)
        interval = 2

        for _ in range(5):
            time.sleep(interval)
            result = self.q(f"tx {txhash}", ignore_errors=True)
            if result:
                return

    def compute_salt(self, contract):
        string = f"{self.address} {contract.code} {contract.label}"
        salt = hashlib.sha256(string.encode("utf-8")).hexdigest()
        return salt

    def build_address(self, contract: Contract):
        self.handle_code(contract.code)

        salt = self.compute_salt(contract)

        code = self.codes.get(contract.code)
        if not code:
            error(f"code not found", name=contract.code)

        code_hash = code.hash

        query = f"wasm build-address {code_hash} {self.address} {salt}"
        return self.q(query, False, False)

    def get_contract_config(self, address):
        debug("get contract config", address=address)
        query = '{"config":{}}'
        response = self.q(
            f"wasm contract-state smart {address} {query}", ignore_errors=True
        )
        if response:
            config = response.get("data")
            config["address"] = address
            return config

        return None

    def instantiate_contract(self, contract):
        if not contract.msg.get("owner"):
            contract.msg["owner"] = self.address

        info("instantiate contract", name=contract.code, label=contract.label)
        debug(None, msg=contract.msg)
        code = self.codes[contract.code]
        code_id = self.code_ids[code.hash]
        salt = self.compute_salt(contract)
        args = json.dumps(contract.msg)

        command = [
            "wasm", "instantiate2", code_id, args, salt,
            "--label", contract.label, "--admin", self.address
        ]

        if contract.funds:
            command += ["--amount", contract.funds]

        self.tx(command)

    def create_denom(self, nonce):
        self.tx(f"denom create-denom {nonce}", ignore_errors=True)
        return f"factory/{self.address}/{nonce}"

    def handle_denom(self, params):
        info("handle denom", **params)
        name = params.get("name")
        if not name:
            error("name not found")

        path = params.get("path")
        if not path:
            nonce = params.get("nonce")
            if not nonce:
                error(f"no path or nonce found for {name}")

            path = self.create_denom(nonce)

        self.denoms[name] = {"name": name, "path": path}

    def handle_contract(self, definition):
        template = Template(json.dumps(definition))
        params = {
            "denoms": Class(self.denoms),
            "contracts": [Class(x) for x in self.contracts],
        }

        rendered = template.render(**params)
        contract = Contract(json.loads(rendered))

        # generate address
        address = self.build_address(contract)

        # query address
        config = self.get_contract_config(address)

        if config:
            info("contract already exists", address=address)
            debug(None, config=config)
            self.add_contract(address, config)
            return

        info("contract not found", address=address)

        self.instantiate_contract(contract)
        config = self.get_contract_config(address)
        self.add_contract(address, config)

    def add_contract(self, address, config):
        config["address"] = address
        self.contracts.append(config)

    def load_blueprint(self, name):
        filename = f"./blueprints/{name}.yml"
        if not os.path.isfile(filename):
            error(f"{filename} not found")

        return yaml.safe_load(open(filename, "r").read())


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("planfile")
    parser.add_argument("-d", "--debug", action="store_true")
    parser.add_argument("-w", "--wasm", nargs="+", default=[])
    return parser.parse_args()


def error(message, **kwargs):
    log(message, logging.ERROR, kwargs)
    sys.exit(1)


def debug(message, **kwargs):
    log(message, logging.DEBUG, kwargs)


def info(message, **kwargs):
    log(message, logging.INFO, kwargs)


def log(message, level, kwargs):
    tags = []
    for k, v in kwargs.items():
        tags.append(f"{k}={v}")

    tags = ", ".join(tags)

    if message:
        message = f"{message} {tags}"
    else:
        message = tags

    logging.log(level, message)


def main():
    args = parse_args()

    log_level = logging.INFO
    if args.debug:
        log_level = logging.DEBUG

    logging.basicConfig(
        level=log_level,
        format="%(levelname)s %(message)s"
    )

    logging.addLevelName(logging.DEBUG, "DBG")
    logging.addLevelName(logging.INFO, "INF")
    logging.addLevelName(logging.WARNING, "WRN")
    logging.addLevelName(logging.ERROR, "ERR")

    deployer = Deployer("kujirad-03985a2", "pond-1", "deployer", args.wasm)

    plan = yaml.safe_load(open(args.planfile, "r"))

    for denom in plan.get("denoms"):
        deployer.handle_denom(denom)

    for contract in plan.get("contracts"):
        deployer.handle_contract(contract)


if __name__ == "__main__":
    main()
