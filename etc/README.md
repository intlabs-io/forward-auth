# README

Forward-auth access rules are defined in two files:

- base.json: the base access rules for forward-auth itself
- access.json: the application access rules which you define to control access to your application(s)

Generate base.json by editing owner.env, setting the environment variables for your deployment.
If you are using metalogic/access-apis for user authentication and roles, the value of OWNER_UID
should be the UID of your tenant defined there. The tenant UID appears in the login response for
your users.

Then run init.sh to generate base.json. 

**The base.json.tmpl template file controls access to the forward-auth API and SHOULD NOT be edited.**

The access control checks for your application belongs in access.json. There is a "blank" access.json
that can be used to begin with. Verify that your deployment of forward-auth works with it before editing
it to add your own access control rules.

Copy base.json and the blank access.json to the etc/forward-auth directory you configured in your
Kustomize manifest.

As you build out your application edit access.json to define the checks on all application endpoints.

