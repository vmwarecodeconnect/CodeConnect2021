"""
FLOW:
-----------------------------------------------------------------------------------------------------------------------
Get alerts with a specific minimum severity.
Based on a alert check whether there is increase of file modifications by getting average count for the week prior
to the alert and for the alert date.
If there is an increase print a message.
Also for an alert get the net con events and check whether RDP connections has been performed and if yes, check
whether the devices have installed sensors, if not advise the customer to install a sensor for better security.

OPTIONS:
-----------------------------------------------------------------------------------------------------------------------
* Send email
* Add to watchlist
* Ban processes with high severity
* Change the policy
* Delele the file
* Quarantine the device
"""
import datetime

from cbc_sdk import CBCloudAPI
from cbc_sdk.endpoint_standard import Policy, EnrichedEvent
from cbc_sdk.enterprise_edr import Report, Watchlist, IOC_V2
from cbc_sdk.platform import ReputationOverride, Device
from cbc_sdk.platform.alerts import CBAnalyticsAlert


def inner_menu(sha256, file_path, device_id):
    """Inner menu"""
    print()
    print("{:^60}".format("Please choose what to do:"))
    print("-" * 60)
    print("1 Nothing")
    print("2 Send an email for re-image or rotate the credentials")
    print("3 Add {} to watchlist".format(sha256))
    print("4 Ban the process {}".format(sha256))
    print("5 Change the policy to more strict")
    print("6 Delete the file {} from the machine".format(file_path))
    print("7 Quarantine the device {}".format(device_id))
    print("0 Exit")
    return int(input())
    print("-" * 60)

def get_netconn(cb):
    """Get the netconn events originated from RDP and check whether there is a sensor on those devices

    Args:
        cb (object): CBCloudAPI
    """
    query = cb.select(EnrichedEvent).add_criteria("event_type", "netconn")
    query = query.where("netconn_port: 22 OR netconn_port: 3389")
    for event in query:
        found_device = None
        devices = cb.select(Device).where(event.event_network_remote_ipv4)
        if len(devices) == 0:
            print("Consider installing a sensor on {}".format(event.event_network_remote_ipv4))
            break
        elif len(devices) > 1:
            for device in devices:
                if device.status == "REGISTERED":
                    if found_device is not None:
                        print("Found more than one device with the same name")
                    else:
                        found_device = device
            if found_device.status == "BYPASS":
                print("This device {} is in BYPASS status. Consider changing.".format(found_device.id))
        else:
            print("All good for the netconn events.")


def get_alerts(cb, severity):
    """Get alerts for specific severity

    Args:
        cb (object): CBCloudAPI
    """
    query = cb.select(CBAnalyticsAlert).set_minimum_severity(severity)
    start_time = datetime.datetime.utcnow() - datetime.timedelta(
        days=1
    )
    start_time = "{}Z".format(start_time.isoformat())
    end_time = "{}Z".format(datetime.datetime.utcnow().isoformat())
    query = query.set_time_range("last_update_time", start=start_time, end=end_time)
    for item in query:
        print("Alert category: {}, reason: {}, sha256: {}".format(item.category,
                                                                  item.reason,
                                                                  item.threat_cause_actor_sha256))
        # get treads for file modifications
        get_trends(cb, item.device_id, item.last_update_time)

        # check device status
        check_device_status(cb, item.device_id)

        choice = inner_menu(item.threat_cause_actor_sha256, item.threat_cause_actor_name, item.device_id)
        if choice == 2:
            send_email()
        elif choice == 3:
            add_to_watchlist(cb, item.threat_cause_actor_sha256)
        elif choice == 4:
            ban_process(cb, item.threat_cause_actor_sha256)
        elif choice == 5:
            change_policy(cb, item.device_id)
        elif choice == 6:
            delete_file_with_live_response(cb, item.device_id, item.threat_cause_actor_name)
        elif choice == 7:
            quarantine_device(cb, item.device_id)
        else:
            exit()
        print()


def get_trends(cb, device_id, alert_time):
    """Get the filemods for a week before the alert_date and for this particular date

    Args:
        cb (object): CBCloudAPI
        device_id (int): id of the device
        alert_time (string): datetime of the alert in isoformat
    """
    alert_time_obj = datetime.datetime.strptime(alert_time, "%Y-%m-%dT%H:%M:%S.%fZ")
    start_time_one_day = "{}Z".format((alert_time_obj - datetime.timedelta(days=1)).isoformat())
    end_time = "{}Z".format((alert_time_obj - datetime.timedelta(days=1)).isoformat())
    start_time = "{}Z".format((alert_time_obj - datetime.timedelta(weeks=1)).isoformat())
    avg_filemods = get_num_filemod(cb, device_id, start_time, end_time)
    alert_day_filemods = get_num_filemod(cb, device_id, start_time_one_day, alert_time)

    if avg_filemods < alert_day_filemods:
        print()
        print("There is increase in file modifications compared to last week.")
    else:
        print()
        print("There is no increase in file modifications.")


def get_num_filemod(cb, device_id, start_date, end_date):
    """Get filemods for specific period

    Args:
        cb (object): CBCloudAPI
        device_id (int): id of the device
        start_date (string): start_date in isoformat
        end_date (string): end_date in isoformat
    """
    start_obj = datetime.datetime.strptime(start_date, "%Y-%m-%dT%H:%M:%S.%fZ")
    end_obj = datetime.datetime.strptime(end_date, "%Y-%m-%dT%H:%M:%S.%fZ")
    delta = (end_obj - start_obj).days
    query = cb.select(EnrichedEvent).set_time_range(start=start_date, end=end_date)
    query = query.add_criteria("event_type", "filemod").add_criteria("device_id", [str(device_id)]).set_rows(10000)
    return len(query) / delta


def check_device_status(cb, device_id):
    """Checking the status of the device

    Args:
        cb (object): CBCloudAPI
        device_id (int): id of the device
    """
    device = cb.select(Device, device_id)
    if device.status == "BYPASS":
        print("This device is in BYPASS status. Consider changing.")


def add_to_watchlist(cb, hash):
    """Add the IOC to a watchlist

    Args:
        cb (object): CBCloudAPI
        hash (string): hash of the process
    """
    builder = Watchlist.create(cb, "Demo").set_description("Watchlist for Demo")
    watchlist = builder.build()
    watchlist = watchlist.save()
    builder = Report.create(cb, "Demo report", "Report for Demo", 5)
    builder.add_ioc(IOC_V2.create_query(cb, "evil-connect", "process_hash:{}".format(hash)))
    report = builder.build()
    report.save_watchlist()
    watchlist.add_reports([report])
    print("Added to watchlist")


def ban_process(cb, hash):
    """Ban the hash of the process

    Args:
        cb (object): CBCloudAPI
        hash (string): hash of the process
    """
    ReputationOverride.create(
        cb,
        {
            "sha256_hash": "{}".format(hash),
            "override_type": "SHA256",
            "override_list": "BLACK_LIST",
            "filename": "",
            "description": "Banned for Demo",
        },
    )
    print("The process hash {} has been added to the black list".format(hash))


def change_policy(cb, device_id):
    """Change the policy of a device

    Args:
        cb (object): CBCloudAPI
        device_id (int): id of the device
    """
    device = cb.select(Device, device_id)
    print("Current policy is {}.".format(device.policy_name))
    api = CBCloudAPI(profile="prod02_api")
    policies = api.select(Policy)
    policy_list = [(item.id, item.name) for item in policies]
    print("{:^60}".format("Available policies:"))
    print("-" * 60)
    for idx, val in enumerate(policy_list):
        print(idx, val[1])
    choice = int(input("Choose new policy number: "))
    device.update_policy(policy_list[choice][0])
    print("Policy has been changed to {}".format(policy_list[choice][1]))


def delete_file_with_live_response(cb, device_id, file_name):
    """Delete a file using Live Response

    Args:
        cb (object): CBCloudAPI
        device_id (int): id of the device
        file_name (string): full path of the file to be deleted
    """
    device = cb.select(Device, device_id)
    lr_session = device.lr_session()
    print("Started session {} with device {}".format(lr_session.session_id, device.name))

    choice = input("Are you sure you would like to delete {} (y/N)".format(file_name))
    if choice == "y":
        lr_session.delete_file(file_name)
        print("File has been deleted!")
    else:
        print("File was not deleted")


def quarantine_device(cb, device_id):
    """Quarantine a device

    Args:
        cb (object): CBCloudAPI
        device_id (int): id of the device
    """
    device = cb.select(Device, device_id)
    device.quarantine(True)
    print("The device has been quarantined")


def send_email():
    """Send a mail"""
    print("Email was sent for re-image or rotate the credentials!")


def main():
    print("-" * 60)
    cb = CBCloudAPI(profile="prod02")
    print('1 Find RDP or SSH connections from devices without a sensor')
    print('2 Get alerts')
    choice = int(input())
    print("-" * 60)
    if choice == 1:
        get_netconn(cb)
    else:
        severity = int(input("Please enter minimum severity: "))
        print("-" * 60)
        get_alerts(cb, severity)


if __name__ == "__main__":
    main()
