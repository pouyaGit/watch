from ai.llm.openrouter import OpenRouterProvider


def main():
    llm = OpenRouterProvider()

    response = llm.generate(
        """
You are a cybersecurity research assistant.

Explain the following hypothetical vulnerability:

A web application has an authentication bypass caused by
incorrect authorization checks.

Return:
1. Vulnerability class
2. Root cause
3. What an attacker could potentially achieve
4. What evidence a security researcher should look for

Keep the answer concise.
"""
    )

    print("\n" + "=" * 60)
    print(response)
    print("=" * 60)


if __name__ == "__main__":
    main()