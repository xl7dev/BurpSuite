Used as part of Burps Session Handling
Record a Macro which just gets the page you want to submit (this should give correct wicket:interface in the form)
Add a new Rule in Options/Sessions
Set the scope (e.g. Repeater/Scanner/Intruder)
Add the Macro to the rule and tick 'After running the macro, invoke a Burp extension action handler'
Select the WicketRequestHandler