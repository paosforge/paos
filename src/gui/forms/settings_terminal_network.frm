form settings_terminal_network spec=v1
window title=Terminal_network w=600 h=600 x=160 y=16 resizable=0 min_w=600 min_h=600 chrome=standard restore=never
widget type=label id=heading x=24 y=40 w=552 h=24 text=Allowed_provider_hosts_(HTTPS_443) role=label
widget type=label id=status x=24 y=72 w=552 h=24 text=Loading role=status_text
widget type=listview id=providers x=24 y=104 w=552 h=324 text=Empty role=list bind=terminal_network.draft scroll=0
widget type=textfield id=entry x=24 y=440 w=552 h=32 text=_ role=textbox
widget type=button id=add x=24 y=484 w=168 h=32 text=Add_host role=button
widget type=button id=remove x=216 y=484 w=168 h=32 text=Remove_selected role=button
widget type=button id=clear x=408 y=484 w=168 h=32 text=Clear_all role=button
widget type=button id=save x=216 y=540 w=168 h=32 text=Save role=button
widget type=button id=cancel x=408 y=540 w=168 h=32 text=Cancel role=button
