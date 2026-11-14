form guest_policy spec=v1
window title=Guest_command_status w=620 h=440 x=180 y=160 resizable=0 min_w=620 min_h=440 chrome=standard restore=never
widget type=listview id=guest_policy_status x=16 y=56 w=588 h=224 text=Guest_command_status role=table bind=guest.policy scroll=0
widget type=button id=policy_none x=16 y=304 w=120 h=32 text=Set_None role=button
widget type=button id=wait_status x=16 y=348 w=132 h=32 text=STATUS:_off role=button
widget type=button id=wait_begin x=156 y=348 w=132 h=32 text=BEGIN:_off role=button
widget type=button id=wait_poll x=296 y=348 w=132 h=32 text=POLL:_off role=button
widget type=button id=wait_cancel x=436 y=348 w=168 h=32 text=CANCEL:_off role=button
widget type=button id=policy_custom x=436 y=392 w=168 h=32 text=Apply_Custom role=button
