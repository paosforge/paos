form sysprops spec=v1
window title=About_this_PC w=800 h=744 x=320 y=80 resizable=1 min_w=800 min_h=390 chrome=standard restore=fresh
widget type=listview id=device_specs x=16 y=60 w=376 h=264 text=Device_specifications role=table bind=sysprops.device scroll=0
widget type=button id=device_copy x=302 y=60 w=90 h=24 text=Copy role=button
widget type=listview id=paos_specs x=408 y=60 w=376 h=264 text=PaOS role=table bind=sysprops.os scroll=0
widget type=button id=os_copy x=694 y=60 w=90 h=24 text=Copy role=button
widget type=button id=advanced_details x=16 y=340 w=240 h=30 text=Show_Advanced_details role=button
widget type=button id=details_next x=272 y=340 w=160 h=30 text=Next_details role=button
widget type=listview id=facts x=16 y=380 w=768 h=330 text=Advanced_details role=table bind=sysprops.live scroll=0
widget type=button id=update_now x=448 y=340 w=336 h=30 text=Update_now role=button
widget type=label id=device_name x=16 y=40 w=768 h=20 text=Device_name: role=label
