#!/usr/bin/env python3

import argparse
import subprocess
import os
import hashlib
import json
import yaml
import logging
import sys
import requests
from mako.template import Template
import base64
import time
from urllib.parse import urlparse
import glob


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
    def __init__(self, source, hash=None):
        self.hash = hash
        self.code = None
        self.source = source


class Deployer:
    def __init__(self, binary, chain_id, wallet, home, api_host, node):
        debug("init deployer", binary=binary, chain_id=chain_id)

        self.binary = binary
        self.chain_id = chain_id
        self.wallet = wallet

        self.home = home
        self.node = node
        self.tmpdir = "/tmp"

        api_host = api_host.replace("https://", "")
        self.api_url = f"https://{api_host}"

        self.codes = {}
        self.set_codes()

        # map of all available code ids deployed in $chain_id
        # {data_hash: code_id}
        self.code_ids = {}
        self.update_code_ids()

        self.address = "kujira1k3g54c2sc7g9mgzuzaukm9pvuzcjqy92nk9wse"

        self.denoms = {}
        self.contracts = {}

    def set_codes(self):
        dirname = os.path.dirname(__file__)
        filename = f"{dirname}/registry.yml"

        registry = yaml.safe_load(open(filename, "r").read())
        for name, values, in registry.items():
            source = values.get("source")
            if not source:
                continue

            hash = values.get("checksum")

            self.codes[name] = Code(source, hash)

    def handle_code(self, name):
        debug("handle code", name=name)
        code = self.codes.get(name)
        if not code:
            error("code not registered", name=name)

        if not code.code:
            debug("code missing")

            parsed = urlparse(code.source)

            if parsed.scheme == "kaiyo-1":
                code_id = parsed.netloc
                if not code_id:
                    error("code id missing", source=code.source)
                url = f"{self.api_url}/cosmwasm/wasm/v1/code/{code_id}"

                info("download code from mainnet", id=code_id, name=name)
                debug(url=url)

                response = requests.get(url)
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
                    message = f"code already deployed on {self.chain_id}"
                    info(message, id=code_id)
                    self.codes[name].id = code_id
                    return

                self.deploy_code(name)

        return self.codes[name].hash

    def get_deployed_codes(self):
        codes = {}
        for name, code in self.codes.items():
            if not code.hash:
                continue
            id = self.code_ids.get(code.hash)
            if not id:
                continue
            codes[name] = {
                "hash": code.hash,
                "id": id
            }

        return codes

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
                "--chain-id", self.chain_id, "--output", "json",
            ]

            if self.node:
                command += ["--node", self.node]

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
            "--chain-id", self.chain_id, "--output", "json",
            "--from", self.wallet, "--keyring-backend", "test",
            "--gas", "auto", "--gas-adjustment", "2", "--yes",
        ]

        if self.node:
            command += ["--node", self.node]

        debug("send transaction", command=" ".join(command))

        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode != 0:
            if ignore_errors:
                return None
            else:
                error(result.stderr)

        result = json.loads(result.stdout)
        debug(result=result)
        txhash = result.get("txhash")
        if txhash:
            self.wait_for(txhash)

        return result

    def wait_for(self, txhash):
        info("wait for tx", hash=txhash)
        interval = 2

        for _ in range(5):
            time.sleep(interval)
            result = self.q(f"tx {txhash}", ignore_errors=True)
            if result:
                return

    def compute_salt(self, contract):
        code = self.codes[contract.code]
        code_id = self.code_ids[code.hash]
        string = f"{self.address} {code_id} {contract.label}"
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
        debug(msg=contract.msg)
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
        info("create denom", nonce=nonce)
        self.tx(f"denom create-denom {nonce}", ignore_errors=True)
        return f"factory/{self.address}/{nonce}"

    def handle_denom(self, params):
        debug("handle denom", name=params["name"])
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
        code = definition["code"]
        name = definition["name"]
        debug("handle contract", code=code)
        template = Template(json.dumps(definition))
        params = {
            "denoms": Class(self.denoms),
            "contracts": Class(self.contracts),
        }

        rendered = template.render(**params)
        contract = Contract(json.loads(rendered))

        # generate address
        address = self.build_address(contract)

        # query address
        config = self.get_contract_config(address)

        if config:
            info("contract already exists", code=code, address=address)
            debug(config=config)
            self.add_contract(name, config, address)
            return

        debug("contract not found", address=address)

        self.instantiate_contract(contract)
        config = self.get_contract_config(address)
        self.add_contract(name, config, address)

    def add_contract(self, name, config, address):
        config["address"] = address
        self.contracts[name] = config


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("planfile", nargs="*")
    parser.add_argument("-d", "--debug", action="store_true")
    parser.add_argument("-b", "--binary", default="kujirad")
    parser.add_argument("--chain-id", default="pond-1")
    parser.add_argument("--wallet", default="deployer")
    parser.add_argument("--home", default="~/.pond/kujira1-1")
    parser.add_argument("--node")
    parser.add_argument("--api-host",
                        default="rest.cosmos.directory/kujira")
    parser.add_argument("--pond-json", default="~/.pond/pond.json")
    return parser.parse_args()


def error(message=None, **kwargs):
    log(message, logging.ERROR, kwargs)
    sys.exit(1)


def warning(message=None, **kwargs):
    log(message, logging.WARNING, kwargs)


def debug(message=None, **kwargs):
    log(message, logging.DEBUG, kwargs)


def info(message=None, **kwargs):
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

    home = os.path.expanduser(args.home)

    deployer = Deployer(
        args.binary, args.chain_id, args.wallet, home, args.api_host, args.node
    )

    planfiles = []

    for string in args.planfile:
        if os.path.isdir(string):
            planfiles += glob.glob(f"{string}/*.yml")
        elif os.path.isfile(string):
            planfiles.append(string)

    for planfile in planfiles:
        plan = yaml.safe_load(open(planfile, "r"))

        # reset contract config
        deployer.contracts = {}

        for denom in plan.get("denoms"):
            deployer.handle_denom(denom)

        for contract in plan.get("contracts"):
            deployer.handle_contract(contract)

    if args.pond_json:
        filename = os.path.expanduser(args.pond_json)
        debug("update pond info", file=filename)

        if not os.path.isfile(filename):
            warning("file not found", file=filename)
            return

        codes = deployer.get_deployed_codes()
        if codes:
            data = json.load(open(filename, "r"))
            data["codes"] = codes
            json.dump(data, open(filename, "w"))


if __name__ == "__main__":
    main()
