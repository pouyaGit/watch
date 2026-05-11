# test_telegram.py
from database.telegram import send_message

# Test 1: Simple message
print("Test 1: Sending simple message...")
result = send_message("✅ Test message from new structure")
print(f"Result: {'Success' if result else 'Failed'}\n")

# Test 2: HTML formatted message
print("Test 2: Sending HTML formatted message...")
result = send_message(
    "🔥 <b>Bold text</b>\n"
    "<code>code block</code>\n"
    "<i>italic text</i>"
)
print(f"Result: {'Success' if result else 'Failed'}\n")

# Test 3: Simulate notification
print("Test 3: Simulating real notification...")
from database.notifications import notify_new_live_subdomain
notify_new_live_subdomain("test.example.com", "TestProgram")
print("Done!")
