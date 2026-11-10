"""WPA-Enterprise evil twin: a rogue 802.1X authenticator that harvests EAP identities and
MSCHAPv2 / GTC / PAP credentials, in the style of eaphammer / hostapd-wpe but native to wifit3.

Submodules are imported directly (``.campaign``, ``.eap_server``, ``.fake_ap``) so that importing
the EAP primitives does not drag in the Textual/campaign stack.
"""
