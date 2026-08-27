from ai.researcher.researcher import SecurityResearcher


def main():
    researcher = SecurityResearcher()

    result = researcher.research(
        title="Hypothetical authentication bypass",
        content="""
A web application contains an authorization flaw.

A server-side endpoint incorrectly trusts a client-controlled
role parameter and fails to verify the authenticated user's
actual permissions.

An attacker may be able to access functionality intended only
for administrators.

The issue affects versions 2.0 through 2.4 of the hypothetical
application.

No CVE identifier is provided.
"""
    )

    print("\n" + "=" * 60)
    print(result.model_dump_json(indent=2))
    print("=" * 60)


if __name__ == "__main__":
    main()