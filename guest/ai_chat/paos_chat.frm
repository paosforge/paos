form paos_chat spec=v1
window title=PaOS_Chat w=640 h=420 x=80 y=80 resizable=1 min_w=480 min_h=340 chrome=standard restore=never
widget type=label id=chat_provider x=16 y=48 w=600 h=24 text=Cloud:_Claude role=label
widget type=button id=chat_claude x=16 y=80 w=160 h=28 text=Cloud:_Claude role=button on_click=CHAT_CLAUDE
widget type=button id=chat_codex x=184 y=80 w=160 h=28 text=Cloud:_Codex role=button on_click=CHAT_CODEX
widget type=button id=chat_local x=352 y=80 w=160 h=28 text=Local_model role=button on_click=CHAT_LOCAL
widget type=textfield id=chat_prompt x=16 y=120 w=600 h=28 text=_ role=textbox
widget type=button id=chat_snapshot x=16 y=160 w=200 h=28 text=Include_screen role=button on_click=CHAT_SNAPSHOT
widget type=button id=chat_send x=232 y=160 w=120 h=28 text=Send role=button on_click=CHAT_SEND
widget type=button id=chat_cancel x=368 y=160 w=120 h=28 text=Cancel role=button on_click=CHAT_CANCEL
widget type=label id=chat_status x=16 y=204 w=600 h=24 text=Not_connected role=status_text
widget type=label id=chat_reply x=16 y=244 w=600 h=128 text=Answers_are_advisory. role=label
