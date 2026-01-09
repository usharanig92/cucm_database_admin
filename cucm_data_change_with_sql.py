# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "paramiko",
#     "click",
#     "inquirer",
# ]
# ///


import sys
import time
import traceback
from typing import Any

import paramiko


def create_ssh_connection(
    hostname: str,
    username: str,
    password: str,
    port: int,
    num_attempts: int = 5,
) -> paramiko.Channel:
    """
    Establishes an SSH connection and returns the client.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for attempt in range(num_attempts):
        print(
            f"Trying to connect to {hostname}, {attempt + 1} out of {num_attempts} attempts"
        )
        try:
            client.connect(
                hostname=hostname,
                username=username,
                password=password,
                timeout=10,
                port=port,
            )

            transport = client.get_transport()
            if transport is not None and transport.is_active():
                print(f"Connected to {hostname}")
                shell = client.invoke_shell()
                return shell
        except paramiko.AuthenticationException:
            formatted_exc = traceback.format_exc()
            print(f"Authentication failed to the host {hostname}: {formatted_exc}")
        except Exception:
            formatted_exc = traceback.format_exc()
            print(f"SSH connection failed to the host {hostname}: {formatted_exc}")
        time.sleep(10)
    print(f"Failed to connect to {hostname} after {num_attempts} attempts")
    raise


def read_from_channel_until_output_matches(
    channel: paramiko.Channel, condition: Any
) -> str:
    output = ""
    while not condition(output):
        output += channel.recv(1024).decode("utf-8")

    return output


class InitializedCiscoShell:
    """Class to get the initialized Cisco shell"""

    def __init__(self, *, hostname: str, username: str, password: str):
        self.channel = create_ssh_connection(
            hostname=hostname, username=username, password=password, port=22
        )

        MAX_TIME_FOR_CUCM_TO_RESPOND = 180.0
        self.channel.settimeout(MAX_TIME_FOR_CUCM_TO_RESPOND)

        read_from_channel_until_output_matches(
            self.channel,
            (lambda output: "admin:" in output),
        )


def execute_sql_query(shell, sql) -> None:
    print(f"Sending command to Cisco: {sql}")
    try:
        shell.channel.sendall((sql + "\n").encode())
        output = read_from_channel_until_output_matches(
            shell.channel, (lambda output: "Rows:" in output)
        )
        print(f"Received output from Cisco: {output}")
        time.sleep(0.5)
    except Exception:
        print(f"Received exception from Cisco: {traceback.format_exc()}")
    return


# Updates all line CSS and call forward CSS.
def update_css(Global_CSS, shell, number):
    for old_css, new_css in Global_CSS.items():
        sql = f"run sql update numplan set fkcallingsearchspace_sharedlineappear=(select pkid from callingsearchspace where name='{new_css}') where fkcallingsearchspace_sharedlineappear=(select pkid from callingsearchspace where name='{old_css}') and dnorpattern like '{number}'"
        execute_sql_query(shell, sql)
        sql = f"run sql update callforwarddynamic set fkcallingsearchspace_cfa=(select pkid from callingsearchspace where name='{new_css}') where fkcallingsearchspace_cfa=(select pkid from callingsearchspace where name='{old_css}') and fknumplan in (select pkid from numplan where dnorpattern like '{number}')"
        execute_sql_query(shell, sql)
        sql = f"run sql update callforwarddynamic set fkcallingsearchspace_scfa=(select pkid from callingsearchspace where name='{new_css}') where fkcallingsearchspace_scfa=(select pkid from callingsearchspace where name='{old_css}') and fknumplan in (select pkid from numplan where dnorpattern like '{number}')"
        execute_sql_query(shell, sql)
        sql = f"run sql update numplan set fkcallingsearchspace_cfb=(select pkid from callingsearchspace where name='{new_css}') where fkcallingsearchspace_cfb=(select pkid from callingsearchspace where name='{old_css}') and tkpatternusage=2 and dnorpattern like '{number}'"
        execute_sql_query(shell, sql)
        sql = f"run sql update numplan set fkcallingsearchspace_cfbint=(select pkid from callingsearchspace where name='{new_css}') where fkcallingsearchspace_cfbint=(select pkid from callingsearchspace where name='{old_css}') and tkpatternusage=2 and dnorpattern like '{number}'"
        execute_sql_query(shell, sql)
        sql = f"run sql update numplan set fkcallingsearchspace_cfna=(select pkid from callingsearchspace where name='{new_css}') where fkcallingsearchspace_cfna=(select pkid from callingsearchspace where name='{old_css}') and tkpatternusage=2 and dnorpattern like '{number}'"
        execute_sql_query(shell, sql)
        sql = f"run sql update numplan set fkcallingsearchspace_cfnaint=(select pkid from callingsearchspace where name='{new_css}') where fkcallingsearchspace_cfnaint=(select pkid from callingsearchspace where name='{old_css}') and tkpatternusage=2 and dnorpattern like '{number}'"
        execute_sql_query(shell, sql)
        sql = f"run sql update numplan set fkcallingsearchspace_pff=(select pkid from callingsearchspace where name='{new_css}') where fkcallingsearchspace_pff=(select pkid from callingsearchspace where name='{old_css}') and tkpatternusage=2 and dnorpattern like '{number}'"
        execute_sql_query(shell, sql)
        sql = f"run sql update numplan set fkcallingsearchspace_pffint=(select pkid from callingsearchspace where name='{new_css}') where fkcallingsearchspace_pffint=(select pkid from callingsearchspace where name='{old_css}') and tkpatternusage=2 and dnorpattern like '{number}'"
        execute_sql_query(shell, sql)
        sql = f"run sql update numplan set fkcallingsearchspace_devicefailure=(select pkid from callingsearchspace where name='{new_css}') where fkcallingsearchspace_devicefailure=(select pkid from callingsearchspace where name='{old_css}') and tkpatternusage=2 and dnorpattern like '{number}'"
        execute_sql_query(shell, sql)
        sql = f"run sql update numplan set fkcallingsearchspace_cfur=(select pkid from callingsearchspace where name='{new_css}') where fkcallingsearchspace_cfur=(select pkid from callingsearchspace where name='{old_css}') and tkpatternusage=2 and dnorpattern like '{number}'"
        execute_sql_query(shell, sql)
        sql = f"run sql update numplan set fkcallingsearchspace_cfurint=(select pkid from callingsearchspace where name='{new_css}') where fkcallingsearchspace_cfurint=(select pkid from callingsearchspace where name='{old_css}') and tkpatternusage=2 and dnorpattern like '{number}'"
        execute_sql_query(shell, sql)


def main() -> None:
    from InquirerPy import inquirer

    cucm_node_name = inquirer.text(
        message="Enter the CUCM node name",
    ).execute()
    cucm_node_user = inquirer.text(
        message="Enter the CUCM username which has admin access",
    ).execute()
    cucm_node_password = inquirer.secret(
        message="Enter the password for the above username",
    ).execute()
    shell = InitializedCiscoShell(
        hostname=cucm_node_name, username=cucm_node_user, password=cucm_node_password
    )
    Global_CSS = {
        "Alpha-Primary-CSS": "Outbound-Node-Gamma-CSS",
        "Beta-Routing-CSS": "Inbound-Gateway-Delta-CSS",
        "Gamma-Filter-CSS": "Reroute-Link-Epsilon-CSS",
        "Delta-Trunk-CSS": "Primary-Channel-Zeta-CSS",
        "Epsilon-Reroute-CSS": "Secondary-Path-Theta-CSS",
    }
    Global_PT = {
        "Alpha-Primary-PT": "Outbound-Node-Gamma-PT",
        "Beta-Routing-PT": "Inbound-Gateway-Delta-PT",
        "Gamma-Filter-PT": "Direct-Trunk-Lambda-PT",
        "Sigma-External-PT": "Backup-Gateway-Omega-PT",
    }
    Global_DP = {
        "US-Alpha-Device-DP": "US-Beta-Device-DP",
        "US-Gamma-Device-DP": "US-Sigma-Device-DP",
        "US-Pi-Device-DP": "US-Lambda-Device-DP",
        "US-Sigma-Device-DP": "US-Square-Device-DP",
    }
    Global_RL = {
        "Alpha-Primary-RL": "Outbound-Node-Gamma-RL",
        "Beta-Routing-RL": "Inbound-Gateway-Delta-RL",
        "Gamma-Filter-RL": "Reroute-Link-Epsilon-RL",
        "Delta-Trunk-RL": "Primary-Channel-Zeta-RL",
    }
    patterns = {
        "7293": "54821047",
        "3841": "29376581",
        "9152": "67493028",
        "6074": "38512964",
        "2489": "91047263",
        "5316": "42768135",
        "8627": "75384019",
    }

    response = None
    while response != "exit":
        response = inquirer.select(
            message="Select the item for which you want to manipulate the data? Select exit to exit",
            choices=[
                "Partitions : Updates Partitions for all directory numbers and URIs",
                "device-pools: Updates device pools for all devices",
                "line_attributes: Updates line number,CSS,description,line text label and remove alt ext",
                "Alt_Num: Updates Alt Num mask",
                "Line_Forwards: Updates call forward numbers",
                "Translation_Pattern: Removes unwanted translation patterns, Modifying Called Party Mask",
                "Route_Patterns_Route_list_update: Updates route list for all route patterns",
                "RD-Destination: Update remote profile's destination number and reroute CSS",
                "speed-dials: Updates speed dial numbers to 8 digits",
                "exit",
            ],
        ).execute()

        # Updates Partitions for all directory numbers
        if (
            response
            == "Partitions : Updates Partitions for all directory numbers and URIs"
        ):
            for old, new in Global_PT.items():
                sql = f"run sql update numplanuri set fkroutepartition=(select pkid from routepartition where name='{new}') where fkroutepartition=(select pkid from routepartition where name='{old}')"
                execute_sql_query(shell, sql)
                sql = f"run sql update numplan set fkroutepartition=(select pkid from routepartition where name='{new}') where fkroutepartition=(select pkid from routepartition where name='{old}') and tkpatternusage=2"
                execute_sql_query(shell, sql)

        if response == "device-pools: Updates device pools for all devices":
            for old, new in Global_DP.items():
                # Updates TCT devices
                sql = f"run sql update device set fkdevicepool=(select pkid from devicepool where name='{new}') where fkdevicepool=(select pkid from devicepool where name='{old}') and tkclass=1 and tkmodel=562"
                execute_sql_query(shell, sql)
                # Updates TAB devices
                sql = f"run sql update device set fkdevicepool=(select pkid from devicepool where name='{new}') where fkdevicepool=(select pkid from devicepool where name='{old}') and tkclass=1 and name matches 'TAB-[A-F]*'"
                execute_sql_query(shell, sql)
                sql = f"run sql update device set fkdevicepool=(select pkid from devicepool where name='{new}') where fkdevicepool=(select pkid from devicepool where name='{old}') and tkclass=1 and name matches 'TAB-[G-L]*'"
                execute_sql_query(shell, sql)
                sql = f"run sql update device set fkdevicepool=(select pkid from devicepool where name='{new}') where fkdevicepool=(select pkid from devicepool where name='{old}') and tkclass=1 and name matches 'TAB-[M-R]*'"
                execute_sql_query(shell, sql)
                sql = f"run sql update device set fkdevicepool=(select pkid from devicepool where name='{new}') where fkdevicepool=(select pkid from devicepool where name='{old}') and tkclass=1 and name matches 'TAB-[S-Z]*'"
                execute_sql_query(shell, sql)
                # Updates BOT devices
                sql = f"run sql update device set fkdevicepool=(select pkid from devicepool where name='{new}') where fkdevicepool=(select pkid from devicepool where name='{old}') and tkclass=1 and tkmodel=575"
                execute_sql_query(shell, sql)
                # Updates CSF devices
                sql = f"run sql update device set fkdevicepool=(select pkid from devicepool where name='{new}') where fkdevicepool=(select pkid from devicepool where name='{old}') and tkclass=1 and tkmodel=503"
                execute_sql_query(shell, sql)
                # Updates all SEP devices
                sql = f"run sql update device set fkdevicepool=(select pkid from devicepool where name='{new}') where fkdevicepool=(select pkid from devicepool where name='{old}') and tkclass=1 and name matches 'SEP*'"
                execute_sql_query(shell, sql)
                # Updates RDP devices
                sql = f"run sql update device set fkdevicepool=(select pkid from devicepool where name='{new}') where fkdevicepool=(select pkid from devicepool where name='{old}') and tkclass=20"
                execute_sql_query(shell, sql)
                # Updates CTI port
                sql = f"run sql update device set fkdevicepool=(select pkid from devicepool where name='{new}') where fkdevicepool=(select pkid from devicepool where name='{old}') and tkmodel=72"
                execute_sql_query(shell, sql)

        # Updates numbers, description, line text label
        if (
            response
            == "line_attributes: Updates line number,CSS,description,line text label and remove alt ext"
        ):
            for old, new in patterns.items():
                try:
                    # Updates DN Number
                    sql = f"run sql update numplan set dnorpattern=replace(dnorpattern,{old},{new}) where dnorpattern like '{old}'"
                    execute_sql_query(shell, sql)
                    # Updates all CSS in line including callforward CSS's.
                    update_css(
                        Global_CSS,
                        shell,
                        new,
                    )
                    # Updates description in the new number to remove digits. To update for all number remove where clause.
                    sql = f"run sql update numplan set description=replace(description,description,regex_replace(description, ' - [0-9]+$', '')) where dnorpattern like '{new}'"
                    execute_sql_query(shell, sql)
                    # Updates line text label in the new number to remove digits.To update for all number remove where clause.
                    sql = f"run sql update devicenumplanmap set label=replace(label,label,regex_replace(label, ' - [0-9]+$', '')) where fknumplan in (select pkid from numplan where dnorpattern like '{new}')"
                    execute_sql_query(shell, sql)
                    # Deletes alternate number for the new number. To update for all number remove where clause.
                    sql = f"run sql delete from alternatenumber where pkid in (select pkid from alternatenumber where fknumplan in (select pkid from numplan where dnorpattern like '{new}'))"
                    execute_sql_query(shell, sql)
                except Exception as e:
                    print(f"Unable to update the pattern {old} to {new}, {e}")

        # Updates Alt Num mask
        if response == "Alt_Num: Updates Alt Num mask":
            sql = "run sql update alternatenumber set dnormask=replace(dnormask,'31XXXX','3411XXXX') where dnormask like '31XXXX'"
            execute_sql_query(shell, sql)

        # Updates call forward numbers.
        if response == "Line_Forwards: Updates call forward numbers":
            for old, new in patterns.items():
                sql = f"run sql update callforwarddynamic set cfadestination=replace(cfadestination,'{old}','{new}') where cfadestination like '{old}'"
                execute_sql_query(shell, sql)
                sql = f"run sql update numplan set cfbdestination=replace(cfbdestination,'{old}','{new}') where cfbdestination like '{old}'"
                execute_sql_query(shell, sql)
                sql = f"run sql update numplan set cfbintdestination=replace(cfbintdestination,'{old}','{new}') where cfbintdestination like '{old}'"
                execute_sql_query(shell, sql)
                sql = f"run sql update numplan set cfnadestination=replace(cfnadestination,'{old}','{new}') where cfnadestination like '{old}'"
                execute_sql_query(shell, sql)
                sql = f"run sql update numplan set cfnaintdestination=replace(cfnaintdestination,'{old}','{new}') where cfnaintdestination like '{old}'"
                execute_sql_query(shell, sql)
                sql = f"run sql update numplan set pffintdestination=replace(pffintdestination,'{old}','{new}') where pffintdestination like '{old}'"
                execute_sql_query(shell, sql)
                sql = f"run sql update numplan set pffdestination=replace(pffdestination,'{old}','{new}') where pffdestination like '{old}'"
                execute_sql_query(shell, sql)
                sql = f"run sql update numplan set devicefailuredn=replace(devicefailuredn,'{old}','{new}') where devicefailuredn like '{old}'"
                execute_sql_query(shell, sql)
                sql = f"run sql update numplan set cfurdestination=replace(cfurdestination,'{old}','{new}') where cfurdestination like '{old}'"
                execute_sql_query(shell, sql)
                sql = f"run sql update numplan set cfurintdestination=replace(cfurintdestination,'{old}','{new}') where cfurintdestination like '{old}'"
                execute_sql_query(shell, sql)

        # Removes unwanted translation patterns, Called Party Mask
        if (
            response
            == "Translation_Pattern: Removes unwanted translation patterns, Modifying Called Party Mask"
        ):
            # deleting unwanted patterns
            patterns_to_delete = {
                "5311": "Alpha-Primary-PT",
                "42.3611": "Beta-Routing-PT",
                "32.XXXX": "Gamma-Filter-PT",
                "919197267151": "Blocking-PT",
            }
            for pattern, partition in patterns_to_delete.items():
                sql = f"run sql delete from numplan where pkid in (select pkid from numplan where dnorpattern like '{pattern}' and tkpatternusage=3 and fkroutepartition=(select pkid from routepartition where name='{partition}'))"
                execute_sql_query(shell, sql)

            # Updating Called Party Transform Mask
            for old, new in patterns.items():
                try:
                    sql = f"run sql update numplan set calledpartytransformationmask='{new}' where calledpartytransformationmask='{old}' and tkpatternusage=3"
                    execute_sql_query(shell, sql)
                except Exception as e:
                    print(
                        f"Unable to update calledpartytransformationmask for {old} with {new}, {e}"
                    )

        # Removes unwanted route patterns, Modifying patterns, Partitions, Called Party Mask
        if (
            response
            == "Route_Patterns_Route_list_update: Updates route list for all route patterns"
        ):
            # Updating Route List
            for old, new in Global_RL.items():
                sql = f"run sql update devicenumplanmap set fkdevice=(select pkid from device where name='{new}') where fkdevice=(select pkid from device where name='{old}')"
                execute_sql_query(shell, sql)

        # Updates remote profile's destination number
        if (
            response
            == "RD-Destination: Update remote profile's destination number and reroute CSS"
        ):
            # Updates CSS for RDP
            for old, new in Global_CSS.items():
                # Updates reroute calling search space.
                sql = f"run sql update device set fkcallingsearchspace_reroute=(select pkid from callingsearchspace where name='{new}') where fkcallingsearchspace_reroute=(select pkid from callingsearchspace where name='{old}') and tkmodel=134"
                execute_sql_query(shell, sql)
            for old, new in patterns.items():
                try:
                    sql = f"run sql update remotedestinationdynamic set destination=replace(destination,'{old}','{new}') where destination like '{old}'"
                    execute_sql_query(shell, sql)
                except Exception as e:
                    print(
                        f"Unable to update remote destination for RDP {old} with {new}: {e}"
                    )

        if response == "speed-dials":
            sql = "run sql update speeddial set speeddialnumber=concat('3110',speeddialnumber) where speeddialnumber like '11__'"
            execute_sql_query(shell, sql)


if __name__ == "__main__":
    sys.exit(main())
