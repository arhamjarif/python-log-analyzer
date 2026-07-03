import datetime
# timestamp|event|IP address|user

'''
========== SUMMARY ==========

Total events
Failed logins
Successful logins
Deleted files
Most active user
Most active IP

========== SECURITY ALERTS ==========

-Possible brute-force attack(ip)
-Repeated failed logins from same IP
-Repeated failed logins for same user
-Successful login after multiple failures (user)
Multiple accounts targeted (IP)
-Mass deletion of files in small time (<5 min,user)
-Repeated password changes (3 times in 1 day,user)
-Login of an account from 2 different IPs <1 min
'''
try:
    with open("sample_log.txt") as file:
        total_events = 0
        failed_login = 0
        successful_login = 0
        deleted_file = 0
        users_activity = {} #{user : [activity_count,[last 10 failed login attempts timestamp],[last 10 failed login attempts ip],[last 10 file deletion timestamp],[last 3 password changed timestamps],[last 2 successful login IPs], [last 2 successful login timestamps]]}
        ips_activity = {}
        repeated_failed_logins_users = set()
        repeated_failed_logins_IPs = set()
        successful_login_after_login_failures = set()
        mass_deletion_user = set()
        repeated_password_changes = set()
        login_from_multiple_IPs = set()
        brute_force_attempt = set()
        multiple_users_targeted = set()
        for line in file:
            fields = line.split('|')
            total_events += 1
            if "LOGIN_FAILED" == fields[1]:
                failed_login += 1
            elif "LOGIN_SUCCESS" == fields[1]:
                successful_login += 1
            elif "FILE_DELETED" == fields[1]:
                deleted_file += 1


            if fields[3] in users_activity:
                users_activity[fields[3]][0] += 1
                if fields[1] == "LOGIN_FAILED":
                    users_activity[fields[3]][1].insert(0,fields[0])
                    users_activity[fields[3]][2].insert(0,fields[2])
                    if len (users_activity[fields[3]][1]) == 11:
                        users_activity[fields[3]][1].pop()
                        users_activity[fields[3]][2].pop()
                
                elif fields[1] == "FILE_DELETED":
                    users_activity[fields[3]][3].insert(0,fields[0])
                    if len(users_activity[fields[3]][3]) == 11:
                        users_activity[fields[3]][3].pop()
                elif fields[1] == "PASSWORD_CHANGED":
                    users_activity[fields[3]][4].insert(0,fields[0])
                    if len(users_activity[fields[3]][4]) == 4:
                        users_activity[fields[3]][4].pop()
                elif fields[1] == "LOGIN_SUCCESS":
                    users_activity[fields[3]][5].insert(0,fields[2])
                    users_activity[fields[3]][6].insert(0,fields[0])
                    if len(users_activity[fields[3]][5]) == 3:
                        users_activity[fields[3]][5].pop()
                        users_activity[fields[3]][6].pop()
            else:
                users_activity[fields[3]] = [1,[],[],[],[],[],[]]
                if fields[1] == "LOGIN_FAILED":
                    users_activity[fields[3]][1].append(fields[0])
                    users_activity[fields[3]][2].append(fields[2])
                elif fields[1] == 'FILE_DELETED':
                    users_activity[fields[3]][3].append(fields[0])
                elif fields[1] == "PASSWORD_CHANGED":
                    users_activity[fields[3]][4].append(fields[0])
                elif fields[1] == "LOGIN_SUCCESS":
                    users_activity[fields[3]][5].append(fields[2])
                    users_activity[fields[3]][6].append(fields[0])



            #Repeated failed login attempts from same user
            if len(users_activity[fields[3]][1]) == 10:
                oldest_time = datetime.datetime.fromisoformat(users_activity[fields[3]][1][9])
                newest_time = datetime.datetime.fromisoformat(users_activity[fields[3]][1][0])
                if (newest_time - oldest_time).total_seconds() <= 1800: #30 minutes
                    repeated_failed_logins_users.add(fields[3])

            #Successful login after multiple login failures ()>= 5)
            if(fields[1] == "LOGIN_SUCCESS" and len(users_activity[fields[3]][1]) >= 5):
                oldest_time = datetime.datetime.fromisoformat(users_activity[fields[3]][1][4])
                newest_time = datetime.datetime.fromisoformat(users_activity[fields[3]][1][0])
                successful_login_time = datetime.datetime.fromisoformat(fields[0])
                if (newest_time - oldest_time).total_seconds() <= 180 and (successful_login_time - newest_time).total_seconds() <= 30: #3 minutes
                    successful_login_after_login_failures.add(fields[3])

            #Mass deletion of 10 files within 5 mins by same user
            if len(users_activity[fields[3]][3]) == 10:
                oldest_time = datetime.datetime.fromisoformat(users_activity[fields[3]][3][9])
                newest_time = datetime.datetime.fromisoformat(users_activity[fields[3]][3][0])
                if (newest_time - oldest_time).total_seconds() <= 300: #5 minutes
                    mass_deletion_user.add(fields[3])

            #Password changed 3 times in 1 day
            if len(users_activity[fields[3]][4]) == 3:
                oldest_time = datetime.datetime.fromisoformat(users_activity[fields[3]][4][2])
                newest_time = datetime.datetime.fromisoformat(users_activity[fields[3]][4][0])
                if (newest_time - oldest_time).total_seconds() <= 86400: #1 day
                    repeated_password_changes.add(fields[3])

            #Login to 1 user from 2 IPs < 1 min 
            if len(users_activity[fields[3]][5]) == 2:
                oldest_time = datetime.datetime.fromisoformat(users_activity[fields[3]][6][1])
                newest_time = datetime.datetime.fromisoformat(users_activity[fields[3]][6][0])
                if users_activity[fields[3]][5][0] != users_activity[fields[3]][5][1] and (newest_time - oldest_time).total_seconds() <= 60: #1 minute
                    login_from_multiple_IPs.add(fields[3])

            #Brute force attempt 10 login fails from same IP in under a minute
            if len(users_activity[fields[3]][1]) == 10:
                first_ip = users_activity[fields[3]][2][0]
                same_ip = True
                for ip in users_activity[fields[3]][2]:
                    if first_ip != ip:
                        same_ip = False
                        break
                if same_ip == True:
                    oldest_time = datetime.datetime.fromisoformat(users_activity[fields[3]][1][9])
                    newest_time = datetime.datetime.fromisoformat(users_activity[fields[3]][1][0])
                    if (newest_time - oldest_time).total_seconds() <= 60: #1 minutes
                        brute_force_attempt.add(fields[3])


            if fields[2] in ips_activity:
                ips_activity[fields[2]][0] += 1
                if fields[1] == "LOGIN_FAILED":
                    ips_activity[fields[2]][1].insert(0,fields[0])
                    ips_activity[fields[2]][2].insert(0,fields[3])
                    if len (ips_activity[fields[2]][1]) == 11:
                        ips_activity[fields[2]][1].pop()
                        ips_activity[fields[2]][2].pop()
            else:
                ips_activity[fields[2]] = [1,[],[]] #(ip : [activity_count,[last 10 failed login timestamps],[last 10 failed login users]]}
                if fields[1] == "LOGIN_FAILED":
                    ips_activity[fields[2]][1].append(fields[0])
                    ips_activity[fields[2]][2].append(fields[3])
            
            #Repeated failed login attempts from same IP
            if len(ips_activity[fields[2]][1]) == 10:
                oldest_time = datetime.datetime.fromisoformat(ips_activity[fields[2]][1][9])
                newest_time = datetime.datetime.fromisoformat(ips_activity[fields[2]][1][0])
                if (newest_time - oldest_time).total_seconds() <= 1800: #30 minutes
                    repeated_failed_logins_IPs.add(fields[2])

            #Multiple accounts targeted
            if len(ips_activity[fields[2]][2]) == 10:
                unique_users = set()
                for user in ips_activity[fields[2]][2]:
                    unique_users.add(user)
                if len(unique_users) >= 3:
                    multiple_users_targeted.add(fields[2])



        highest_user_activity = 0
        most_active_user = 'temp'
        for key,value in users_activity.items():
            if value[0] > highest_user_activity:
                most_active_user = key
                highest_user_activity = value[0]


        highest_ip_activity = 0
        most_active_ip = 'temp'
        for key,value in ips_activity.items():
            if value[0] > highest_ip_activity:
                most_active_ip = key
                highest_ip_activity = value[0]
        


        print('========== SUMMARY ==========')
        print(f"\nTotal events:{total_events}\n\nFailed logins:{failed_login}\n\nSuccessful logins:{successful_login}\n\nDeleted files:{deleted_file}\n\nMost active user:{most_active_user.strip()}({highest_user_activity} events)\n\nMost active IP:{most_active_ip} ({highest_ip_activity} events)")
        print('\n\n\n\n========== SECURITY ALERTS ==========')
        print('\nPossible brute-force attack on user:')
        if not brute_force_attempt:
              print('No alerts detected')
        else:
              for i in brute_force_attempt:
                  print(f"{i}  ",end = '')              
              
        print('\nRepeated Failed logins from same IP:')
        if not repeated_failed_logins_IPs:
              print('No alerts detected')
        else:
              for i in repeated_failed_logins_IPs:
                  print(f"{i}  ")   
        
        print('\nRepeated Failed logins from same user:')
        if not repeated_failed_logins_users:
              print('No alerts detected')
        else:
              for i in repeated_failed_logins_users:
                  print(f"{i}  ", end = '')   

        print('\nSuccessful login from user after multiple failures:')
        if not successful_login_after_login_failures:
              print('No alerts detected')
        else:
              for i in successful_login_after_login_failures:
                  print(f"{i}  ", end = '')   

        print('\nMultiple users targetted from IP:')
        if not multiple_users_targeted:
              print('No alerts detected')
        else:
              for i in multiple_users_targeted:
                  print(f"{i}  ")   
        
        print('\nMass Deletion of Files from user in short time:')
        if not mass_deletion_user:
              print('No alerts detected')
        else:
              for i in mass_deletion_user:
                  print(f"{i}  ", end = '')   
        
        print('\nRepeated password change of user:')
        if not repeated_password_changes:
              print('No alerts detected')
        else:
              for i in repeated_password_changes:
                  print(f"{i}  ", end = '')   
        
        print('\nSuccessful login of user from multiple IPs:')
        if not login_from_multiple_IPs:
              print('No alerts detected')
        else:
              for i in login_from_multiple_IPs:
                  print(f"{i}  ", end = '')   

except FileNotFoundError:
    print("Log not found")
