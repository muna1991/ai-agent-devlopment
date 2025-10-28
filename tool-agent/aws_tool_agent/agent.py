import os
import boto3
from datetime import datetime, timezone
from google.adk.agents import Agent
from dotenv import load_dotenv

load_dotenv()

def list_inactive_iam_keys() -> dict:
    """
    Fetch IAM users whose access keys are either:
    - Inactive
    - Active but not used for more than 100 days
    """
    try:
        profile_name = os.getenv("AWS_PROFILE", "default")
        session = boto3.Session(profile_name=profile_name)
        iam_client = session.client("iam")

        users_response = iam_client.list_users()
        users = users_response.get("Users", [])

        inactive_or_unused_keys = []

        for user in users:
            username = user["UserName"]
            keys_response = iam_client.list_access_keys(UserName=username)
            access_keys = keys_response.get("AccessKeyMetadata", [])

            for key in access_keys:
                key_id = key["AccessKeyId"]
                status = key["Status"]
                create_date = key["CreateDate"]
                last_used_info = iam_client.get_access_key_last_used(AccessKeyId=key_id)
                last_used_date = last_used_info["AccessKeyLastUsed"].get("LastUsedDate")

                if last_used_date:
                    days_unused = (datetime.now(timezone.utc) - last_used_date).days
                else:
                    days_unused = (datetime.now(timezone.utc) - create_date).days

                # Filter inactive or old keys
                if status == "Inactive" or days_unused > 100:
                    inactive_or_unused_keys.append({
                        "UserName": username,
                        "AccessKeyId": key_id,
                        "Status": status,
                        "DaysUnused": days_unused,
                        "LastUsedDate": str(last_used_date) if last_used_date else "Never Used",
                        "CreatedOn": str(create_date)
                    })

        if not inactive_or_unused_keys:
            formatted_output = (
                f"✅ No IAM users found with inactive or 100+ day unused keys for profile `{profile_name}`."
            )
        else:
            formatted_output = (
                f"🔐 **AWS Profile:** `{profile_name}`\n"
                f"📅 **Scan Time:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
                f"⚠️ **Summary:** Found `{len(inactive_or_unused_keys)}` access keys that are inactive or unused for more than 100 days.\n"
                f"{'═'*80}\n"
            )

            for idx, item in enumerate(inactive_or_unused_keys, 1):
                formatted_output += (
                    f"\n🧑 **User {idx}: {item['UserName']}**\n"
                    f"├─ 🔑 AccessKeyId : `{item['AccessKeyId']}`\n"
                    f"├─ 🕒 Status      : {('❌ Inactive' if item['Status']=='Inactive' else '⚠️ Active (Unused >100d)')}\n"
                    f"├─ 📆 Days Unused : {item['DaysUnused']} days\n"
                    f"├─ 🗓️ Last Used   : {item['LastUsedDate']}\n"
                    f"└─ 🪪 Created On  : {item['CreatedOn']}\n"
                    f"{'─'*80}\n"
                )

            formatted_output += "\n✅ **Recommendation:** Rotate or delete these unused keys and enforce key rotation policy.\n"

        return {
            "profile_used": profile_name,
            "inactive_or_unused_keys": inactive_or_unused_keys,
            "formatted_output": formatted_output
        }

    except Exception as e:
        return {"error": str(e)}


# Define the Agent
root_agent = Agent(
    name="aws_iam_audit_agent",
    model="gemini-2.0-flash",
    description="Agent that audits IAM access keys for inactivity or disuse beyond 100 days.",
    instruction="""
    You are a helpful assistant that can use the tool `list_inactive_iam_keys`
    to identify IAM users with inactive or long-unused access keys, and format the results neatly as a compliance report.
    """,
    tools=[list_inactive_iam_keys],
)

