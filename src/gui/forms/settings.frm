form settings spec=v1
window title=Settings w=640 h=440 x=720 y=0 resizable=1 min_w=420 min_h=320 chrome=standard restore=fresh
widget type=listview id=facts x=200 y=66 w=432 h=198 text=machine_facts role=table bind=sysprops.live scroll=0
widget type=label id=pref_heading x=200 y=296 w=104 h=24 text=Preferences role=label
widget type=label id=pref_state x=312 y=296 w=320 h=24 text=Time_zone role=status_text
widget type=listview id=zone x=200 y=328 w=104 h=104 text=UTC,Phoenix,New_York,Fixed role=radiogroup value=0 min=0 max=3 step=1 mode=radio
widget type=button id=zone_apply x=536 y=328 w=96 h=32 text=Apply role=button
widget type=button id=zone_cancel x=536 y=364 w=96 h=32 text=Cancel role=button
widget type=button id=zone_reset x=536 y=400 w=96 h=32 text=Reset role=button
widget type=listview id=kbd x=312 y=328 w=104 h=104 text=US,Espanol,Francais,Deutsch role=radiogroup value=0 min=0 max=3 step=1 mode=radio
widget type=listview id=lang x=424 y=328 w=104 h=104 text=English,Spanish,French,German role=radiogroup value=0 min=0 max=3 step=1 mode=radio
widget type=button id=apps x=536 y=266 w=96 h=28 text=Apps role=button
widget type=button id=updates x=200 y=266 w=328 h=28 text=Updates:_Update_now role=button
widget type=label id=device_name x=200 y=40 w=316 h=24 text=Device_name: role=label
widget type=button id=about x=536 y=40 w=96 h=24 text=About role=button
widget type=button id=nav_0 x=8 y=8 w=184 h=24 text=System role=button
widget type=button id=nav_1 x=8 y=36 w=184 h=24 text=Devices role=button
widget type=button id=nav_2 x=8 y=64 w=184 h=24 text=Network role=button
widget type=button id=nav_3 x=8 y=92 w=184 h=24 text=Personalization role=button
widget type=button id=nav_4 x=8 y=120 w=184 h=24 text=Apps role=button
widget type=button id=nav_5 x=8 y=148 w=184 h=24 text=Accounts_and_sign-in role=button
widget type=button id=nav_6 x=8 y=176 w=184 h=24 text=AI role=button
widget type=button id=nav_7 x=8 y=204 w=184 h=24 text=Time_and_language role=button
widget type=button id=nav_8 x=8 y=232 w=184 h=24 text=Accessibility role=button
widget type=button id=nav_9 x=8 y=260 w=184 h=24 text=Privacy_and_security role=button
widget type=button id=nav_10 x=8 y=288 w=184 h=24 text=Files role=button
widget type=button id=nav_11 x=8 y=316 w=184 h=24 text=Updates_and_recovery role=button
widget type=label id=page_title x=200 y=8 w=320 h=24 text=System role=label
widget type=label id=page_later x=200 y=40 w=320 h=24 text=Coming_later role=label
widget type=button id=terminal_network x=200 y=40 w=200 h=28 text=Terminal_network role=button
widget type=label id=nav_badge x=8 y=344 w=184 h=24 text=_ role=status_text
