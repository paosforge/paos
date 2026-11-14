form settings spec=v1
window title=Settings w=500 h=440 x=720 y=0 resizable=1 min_w=420 min_h=320 chrome=standard restore=fresh
widget type=listview id=facts x=24 y=48 w=452 h=216 text=machine_facts role=table bind=sysprops.live scroll=0
widget type=label id=pref_heading x=24 y=272 w=328 h=24 text=Preferences role=label
widget type=label id=pref_state x=24 y=296 w=452 h=24 text=Time_zone role=status_text
widget type=listview id=zone x=24 y=328 w=104 h=104 text=UTC,Phoenix,New_York,Fixed role=radiogroup value=0 min=0 max=3 step=1 mode=radio
widget type=button id=zone_apply x=360 y=328 w=116 h=32 text=Apply role=button
widget type=button id=zone_cancel x=360 y=364 w=116 h=32 text=Cancel role=button
widget type=button id=zone_reset x=360 y=400 w=116 h=32 text=Reset role=button
widget type=listview id=kbd x=136 y=328 w=104 h=104 text=US,Espanol,Francais,Deutsch role=radiogroup value=0 min=0 max=3 step=1 mode=radio
widget type=listview id=lang x=248 y=328 w=104 h=104 text=English,Spanish,French,German role=radiogroup value=0 min=0 max=3 step=1 mode=radio
widget type=button id=apps x=360 y=266 w=116 h=28 text=Apps role=button
