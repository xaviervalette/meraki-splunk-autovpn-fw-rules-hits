import json
import logging
import time

import import_declare_test  # noqa: F401  (sets sys.path to the bundled lib/)
from solnlib import conf_manager, log
from splunklib import modularinput as smi

from meraki_vpnfw_api import MerakiClient
from meraki_vpnfw_signature import rule_signature

ADDON_NAME = "TA-meraki-vpnfw"
CONF_PREFIX = "ta_meraki_vpnfw"
RULE_SOURCETYPE = "meraki:vpnfw:rule"
APPLIANCE_SOURCETYPE = "meraki:vpnfw:appliance"
RULE_FIELDS = ("comment", "policy", "protocol", "srcCidr", "srcPort", "destCidr", "destPort", "syslogEnabled")
APPLIANCE_FIELDS = ("serial", "mac", "name", "model", "networkId", "firmware")


def logger_for_input(input_name: str) -> logging.Logger:
    return log.Logs().get_logger(f"{CONF_PREFIX}_{input_name}")


def get_account(session_key: str, account_name: str) -> dict:
    cfm = conf_manager.ConfManager(
        session_key,
        ADDON_NAME,
        realm=f"__REST_CREDENTIAL__#{ADDON_NAME}#configs/conf-{CONF_PREFIX}_account",
    )
    return cfm.get_conf(f"{CONF_PREFIX}_account").get(account_name)


def org_ids_of(input_item: dict):
    return [o.strip() for o in input_item.get("organization_ids", "").split(",") if o.strip()]


def collect_org(client: MerakiClient, org_id: str, poll_id: int):
    """Yield (sourcetype, payload) for one organization's rules and appliances."""
    org_name = (client.organization(org_id) or {}).get("name", "")
    base = {"poll_id": poll_id, "org_id": org_id, "org_name": org_name}

    rules = client.vpn_firewall_rules(org_id)
    for index, rule in enumerate(rules, start=1):
        is_default = index == len(rules) and rule.get("comment") == "Default rule"
        payload = dict(base, rule_index=index, rule_count=len(rules), is_default=is_default,
                       signature=rule_signature(rule))
        payload.update({f: rule.get(f) for f in RULE_FIELDS})
        yield RULE_SOURCETYPE, payload

    for device in client.appliances(org_id):
        payload = dict(base)
        payload.update({f: device.get(f) for f in APPLIANCE_FIELDS})
        payload["mac"] = (payload.get("mac") or "").lower()
        yield APPLIANCE_SOURCETYPE, payload


def validate_input(definition: smi.ValidationDefinition):
    return


def stream_events(inputs: smi.InputDefinition, event_writer: smi.EventWriter):
    for input_name, input_item in inputs.inputs.items():
        normalized_input_name = input_name.split("/")[-1]
        logger = logger_for_input(normalized_input_name)
        try:
            session_key = inputs.metadata["session_key"]
            logger.setLevel(conf_manager.get_log_level(
                logger=logger,
                session_key=session_key,
                app_name=ADDON_NAME,
                conf_name=f"{CONF_PREFIX}_settings",
            ))
            log.modular_input_start(logger, normalized_input_name)
            account = get_account(session_key, input_item.get("account"))
            client = MerakiClient(account.get("api_key"), account.get("base_url") or "https://api.meraki.com/api/v1",
                                  logger=logger)
            poll_id = int(time.time())
            index = input_item.get("index")
            counts = {RULE_SOURCETYPE: 0, APPLIANCE_SOURCETYPE: 0}

            for org_id in org_ids_of(input_item):
                try:
                    for sourcetype, payload in collect_org(client, org_id, poll_id):
                        event_writer.write_event(smi.Event(
                            data=json.dumps(payload, ensure_ascii=False, default=str),
                            index=index,
                            sourcetype=sourcetype,
                            source=f"meraki_vpnfw_rules://{normalized_input_name}",
                        ))
                        counts[sourcetype] += 1
                except Exception as e:
                    # One bad org (no MX, no API access) must not stop the others.
                    log.log_exception(logger, e, "Meraki API Error",
                                      msg_before=f"Failed to collect organization {org_id}: ")

            for sourcetype, count in counts.items():
                log.events_ingested(logger, input_name, sourcetype, count, index,
                                    account=input_item.get("account"))
            log.modular_input_end(logger, normalized_input_name)
        except Exception as e:
            log.log_exception(logger, e, "Meraki VPN FW Input Error",
                              msg_before="Exception raised while ingesting data for meraki_vpnfw_rules: ")
