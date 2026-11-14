form settings_updates spec=v1
window title=Updates w=560 h=428 x=520 y=80 resizable=0 min_w=560 min_h=428 chrome=standard restore=fresh
widget type=label id=heading x=24 y=48 w=512 h=24 text=Keep_PaOS_up_to_date role=label
widget type=label id=update_state x=24 y=80 w=512 h=24 text=Updates:_open_to_check role=status_text
widget type=button id=check x=24 y=120 w=240 h=32 text=Check_for_updates role=button
widget type=button id=download x=288 y=120 w=248 h=32 text=Download role=button
widget type=button id=restart x=288 y=164 w=248 h=32 text=Restart_to_apply role=button
widget type=button id=automatic x=24 y=212 w=512 h=32 text=Enable_auto_download/apply role=button
widget type=label id=manual x=24 y=264 w=512 h=24 text=Manual_download_is_the_default role=label
widget type=label id=reboot x=24 y=292 w=512 h=24 text=Restart_always_needs_your_OK role=label
widget type=label id=checked_age x=24 y=320 w=512 h=24 text=Not_checked role=label
widget type=button id=daily x=24 y=356 w=512 h=32 text=Daily_check_unavailable role=button
