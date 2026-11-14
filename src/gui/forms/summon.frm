form summon spec=v1
window title=Summon w=560 h=400 x=0 y=0 resizable=0 min_w=560 min_h=400 chrome=standard restore=never
widget type=overlay id=summon_root x=0 y=0 w=560 h=400 text=summon role=dialog overlay_layer=1
widget type=col id=summon_panel parent=summon_root x=0 y=0 w=560 h=400 text=Summon role=group
widget type=textfield id=query parent=summon_root x=24 y=24 w=512 h=30 text=summon.query role=searchbox
widget type=button id=resume parent=summon_root x=24 y=70 w=512 h=30 text=summon.resume role=button
widget type=button id=pinned parent=summon_root x=24 y=116 w=252 h=30 text=summon.pinned role=tab
widget type=button id=recents parent=summon_root x=284 y=116 w=252 h=30 text=summon.recents role=tab
widget type=listview id=results parent=summon_root x=24 y=154 w=512 h=222 text=summon.results role=listbox bind=summon.pinned
