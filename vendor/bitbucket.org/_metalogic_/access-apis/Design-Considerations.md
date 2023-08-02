Ricky's Notes:

For the simple MC_USER role we were talking about this morning I
think that it is an example of a role that has no ROLE_PERMISSIONS -
it simply must be present in the JWT, at least that is the only thing
that makes sense in the context of "You have to have MGT_USER role in
order to access the Management Console".  By itself it gives no
permissions, but does give access to the app.  There may be public
resources that are exposed in MC that such a user could view but
that's about it.

I've created two new records in the ROLES table, MGT_USER and
APPLY_USER (each owned by institution EPBC).  I'm going to create
records for each user that assigns them MGT_USER role in USER_ROLES.

Looking at how the user permissions are embedded in the user identity,
this use of role implies changes.  I think that role can be assigned
category = 'ANY' with actions = 'NONE'.

CATEGORY = ANY, ACTIONS = NONE means there is no action you can
perform on any category.

ANY is the wildcard for category.  ALL is the wildcard for ACTIONS

So the wildcard on category ANY and NONE on actions seems to make
sense.

The Root role has CATEGORY = ANY and ACTIONS = ALL

Once given a role, is the 'ANY' removed? No, everyone has the MGT_USER
role and also CATEGORY = ANY and ACTIONS = NONE

I guess the question is does any role at all allow access to MC.  If so,
then adding a role could cause the 'default' MGT_USER role to be
deleted but this has the disadvantage that if all of the roles are
removed for a user then they have lost access to MC which might not be
intended.  The access control rules are based the presence of a required
permission to access a resource that means that ANY+ALL beats ANY+NONE
so it should work correctly as it is now.

There are different approaches taken by access control systems.  Some
allow each role to indicate whether the default is deny and then
examine the allow rules, or the default is allow and then examine the
deny rules.  This can get complicated very quickly and can turn into
an entire project unto itself (which to an extent it already has).
Once we start working on OAuth it WILL be an entire project.

Mon Apr 27 Discussion with Ricy

Users don't have PSIs, they are autonomous but users ARE assigned
roles in one of more PSIs

Regarding the endpoint api.GET("/users", GetUsers) which is just the
previous get users endpoint but with addition string parameters.

ricky: it is meaningless to add epbcID='EPBC' (or any other EPBCID)
users don't have institutions

As it stands now, the filtering by psi returns users with a role at a
specific PSI.  This is to support the first item in
https://jira.bccampus.ca/browse/EPBCUI-1176

  Create a management interface to be able to perform the following actions:
  List all users, filter by PSI, search by name

ricky: yes - but it isn't really valid - that is what we met about last week

I think we had agreed that we would send an invitation email to a user
to register for an account they would register and have already been
granted MTG_USER role that would allow them to login to MC but do
nothing else an institution admin, knowing that their colleague has an
MC account' can assign a role to that account that is true regardless
of whether they are an employee of the institution or not

Tthe example I gave was Michael from OA who is not an employee of any
PSI yet wouyld probably have some roles for each of the Colleague PSIs

Raymond: Ok, so are you saying we can't have that filter?

ricky: hmm - I guess Im saying that an institution admin wants to look
at the users that have been assigned roles in the PSI

Raymond: It still seems reasonable since Michael would show up for
each psi that he has a contract with during a search

ricky: but it seems to me that request should be incorporated in the
roles editor

Raymond: so the search would return all users with a role at the psi

ricky: if that is useful, then yes but to me this lives under roles
admin UI ie the query to show users of interest to a PSI should come
from user_roles

ricky: it might make sense to get user-rolesfor a specific institution


Raymond: If there was a way to do
api.GET("institutions/:epbcid/users", GetInstUsers) or something
similar.  That would seem the what the requirement specifies.  I only
used roles so I had some handle on the institution.

ricky: the requirement is invalid given the current data model.  It
would make sense to ask what users have roles for a given institution,
maybe GET /institutions/:epbcid/roles/users ?

ricky: if I imagine an institution admin wanting to grant an
institution role to a user; I don't see an alternative to searching
for the user by their name or email (searching for just ubc.ca should
return the primary candidates for assigning UBC roles.  Having that
list I imagine someone selecting a particular user account and
assigning a role to it but I also imagine an institution admin wanting
to come at things from a roles editor and in that editor seeing all
user accounts that have been assigned a role in their institution
