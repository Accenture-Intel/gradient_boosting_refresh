DISCLAIMER = '''
This script is designed to collect information that will help Microsoft Customer Support Services (CSS) troubleshoot issues you may be experiencing with Microsoft Defender for Endpoint.
The logs and traces collected by this tool may contain Personally Identifiable Information (PII) and/or sensitive data, such as (but not limited to) IP addresses, PC names, and user names.
Once data collection is complete, the script will save the data to subfolder and compressed zip file.
This data will not be sent to Microsoft automatically.
You can share the compressed zip file with Microsoft support personnel using Secure File Exchange.
For more information about Secure File Exchange, refer to:
https://support.microsoft.com/help/4012140/how-to-use-secure-file-exchange-to-exchange-files-with-microsoft-suppo
For more information about our privacy statement, refer to:
https://privacy.microsoft.com/privacystatement
Please reach out to your support professional if you have any questions or concerns.
'''

def present_disclaimer():
    prompt_no = ['n', 'no']
    prompt_yes = ['y', 'yes']
    print(DISCLAIMER)
    while True:
        user_input = input(f"Do you wish to continue? [y/n]\n")
        if user_input.lower() not in (prompt_yes + prompt_no):
            continue
        return user_input.lower() in prompt_yes


    