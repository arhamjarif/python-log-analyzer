# timestamp|event|IP address|user
# dict for most active user/ip
try:
    with open("log.txt") as file:
        total_events = 0
        failed_login = 0
        successful_login = 0
        deleted_file = 0
        users_activity = {}
        ips_activity = {}
        for line in file:
            fields = line.split('|')
            total_events += 1
            if "LOGIN_FAILED" in fields[1]:
                failed_login += 1
            elif "LOGIN_SUCCESS" in fields[1]:
                successful_login += 1
            elif "FILE_DELETED" in fields[1]:
                deleted_file += 1
            if fields[3] in users_activity:
                users_activity[fields[3]] += 1
            elif fields[3] not in users_activity:
                users_activity[fields[3]] = 1
            if fields[2] in ips_activity:
                ips_activity[fields[2]] += 1
            elif fields[2] not in ips_activity:
                ips_activity[fields[2]] = 1
        highest_user_activity = 0
        most_active_user = 'temp'
        for key,value in users_activity.items():
            if value > highest_user_activity:
                most_active_user = key
                highest_user_activity = value
        highest_ip_activity = 0
        most_active_ip = 'temp'
        for key,value in ips_activity.items():
            if value > highest_ip_activity:
                most_active_ip = key
                highest_ip_activity = value
        


        print('========== SUMMARY ==========')
        print(f"Total events:{total_events}\nFailed logins:{failed_login}\nSuccessful logins:{successful_login}\nDeleted files:{deleted_file}\nMost active user:{most_active_user}({highest_user_activity} logins)\nMost active IP:{most_active_ip} ({highest_ip_activity} logins)")
        
except FileNotFoundError:
    print("Log not found")
