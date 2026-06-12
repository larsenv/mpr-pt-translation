import subprocess
import struct
import binascii
import calendar
from datetime import datetime, timezone


def log(msg, level="INFO"):
    print(f"[{level}] {msg}")


def u8(data):
    if not 0 <= data <= 255:
        log(f"u8 out of range: {data}", "INFO")
        data = 0
    return struct.pack(">B", data)


def u16(data):
    if not 0 <= data <= 65535:
        log(f"u16 out of range: {data}", "INFO")
        data = 0
    return struct.pack(">H", data)


def u32(data):
    if not 0 <= data <= 4294967295:
        log(f"u32 out of range: {data}", "INFO")
        data = 0
    return struct.pack(">I", data)


def crc16_xmodem(data, crc=0):
    poly = 0x1021
    for byte in data:
        crc ^= (byte << 8)
        for _ in range(8):
            crc = (crc << 1) ^ poly if (crc & 0x8000) else crc << 1
            crc &= 0xFFFF
    return crc


opening_timestamp = int(calendar.timegm(datetime.now(timezone.utc).timetuple())) - 946684800

pokemon = ["", "", "", "B0514907000012EA03E2243BA248E7DFBF81BE3F675769D38AAD942D08CE6CA89805E09F446BE7007525F0A541CB06E1FFDB3127A010751CEE6D53D48F5EE88E66FA13015A32250546496302F6AD8CECAB6AEE96F0E5CEB37253D7F8C8BD8C9DA8D7B1C180E361A11B1496F56510A40B9DB7958DEED9015E532E6F482F0AEBF246353B24838D8766", ""]

mii = ["80060041006B006900790061006D006100000000000040408836A1113A017D6284003E00017D0891A48B084084485AAE008A008A25040000000000000000000000000000000000000000", "8008004200610062006100690067006F006E0000000040408836A0223A017D6240004400017D06A2684C08608640784E008A008A25040000000000000000000000000000000000000000", "80160047006F006C006B006F00000000000000000000404088369F123A017D6284002E00613D08611CAA0640743020CE008A402625040000000000000000000000000000000000000000", "000230EC30C330C9306F304B305B00000000000000007F408108E2EFC2EFA02E44C43E00918008737C890460333030EC8280028A25040000000000000000000000000000000000000000", "C00E00590075006B0069006E0061000000000000000040408836A0623A017D6220008F8001BD24A38C6B06A06438B0AD008A008A8C580000000000000000000000000000000000000000"]

# Text converted to clear dictionaries mapped to their functional names
text = [
    {
        "ja_JP": {
            "dialog_1": "ポケモーニング！\nあきやまたいいんだよ\0",
            "exchange_1": "コイキングをつれてくると、ケッキングと\nこうかんしてくれるそうです。\0",
            "mail_1": "", "mail_2": "", "dialog_2": "", "dialog_3": "", "name_1": "", "name_2": "", "pad": ""
        }
    },
    {
        "ja_JP": {
            "dialog_1": "",
            "exchange_1": "すこい！ムックルをつれてきて\nさっそくこうかんしよう。\0",
            "mail_1": "", "mail_2": "", "dialog_2": "", "dialog_3": "", "name_1": "", "name_2": "", "pad": ""
        }
    },
    {
        "ja_JP": {
            "dialog_1": "やあみんな、ポケサンカンパニーの\nゴルゴしょちょうだ。\nポケモン★サンデーをみて、もっと\nポケモンをすきになってくれよな。                                                  ",
            "exchange_1": "じつはな、ジグサクマを\n25ひきあつめると\nジグザグパレードをするんじゃ。\nわしは、と〜ってもそれがみたい！\0",
            "mail_1": "ぜひ、キミの ジグサグマと\nわしの オクタンを\nこうかんしようじゃないか。\0",
            "mail_2": "たのしかった!\nほんとにありがとう。\nこのなつは、\nえいがかんで あおうね！\0",
            "dialog_2": "",
            "dialog_3": "わしは、しばらくほくじょうで\nあそんでいくぞ。いいな？\0",
            "name_1": "ジグザグマをつれてくると\nオクタンと\nこうかんしてくれるそうです。\0",
            "name_2": "お、ジグザグマを\nつれてきてくれたのかい。\nさっそく こうかんしょうじゃないか。\0",
            "extra": "ゴルゴしょちょう\0",
            "pad": ""
        }
    },
    {
        "en_US": {
            "dialog_1": "PokéMorning!\nDid you happen to see me on Pokémon Sunday?\nI'm Professor Red!\n                                    \nI brought my METAGROSS, Homerun!\0",
            "exchange_1": "Oh, that's MACHOP!\nYou brought it for me, right?\nThank you.\nSo, let's trade.\0",
            "mail_1": "I have to return to\nthe PokéSun Company soon...\nLet's meet again on Pokémon Sunday!\nPoké we.. GO!\0",
            "mail_2": "P.S.\nThank you for trading for METAGROSS.\nMy Homerun is really strong~!\nPlease take good care of it!\0",
            "dialog_2": "Well, actually, I heard an amazing\nrumor that if you \ngather 8 Fighting Type Pokémon in the new ranch,\nthey'll have a Tournament\n                                           \nI wonder, would you trade your MACHOP for my Homerun?\0",
            "dialog_3": "I'm going to watch the Pokémon on the ranch for a while.\0",
            "name_1": "Professor Red\0",
            "name_from": "From Professor Red\0"
        },
        "ja_JP": {
            "dialog_1": "ポケモーニング!\n「ポケモン☆サンデー」での わたしの\nかつやくを みてくれているかな?\nレッドはかせです!\n                                   \nわたしのメタグロス、ホームランを\nつれてきちゃいました～!\0",
            "exchange_1": "お、それはワンリキー!\nつれてきてくれたんですね。\nありがとう。\nでは、こうかんしましょうか。\0",
            "mail_1": "そろそろ ポケサンカンパニーに \r\nかえらなくては……\r\nまた 「ポケモン☆サンデー」で\r\nあいましょう!\r\nポケ・ウィー・ゴー!\0",
            "mail_2": "P.S.\r\nメタグロスと\r\nこうかんしてくれて、ありがとう。\r\nわたしの ホームランは\r\nつよいですよ～!\r\nちゃんと かわいがってくださいね!\0",
            "dialog_2": "いや～、じつはですね、すごいウワサを \nみみにしたんですが、\n                                      \nあたらしいぼくじょうで、\nかくとうタイプの ポケモンを 8ぴき \nあつめると、トーナメントを \nするらしいんですよね～。\n                                          \nすっごく きになってるんですが、 \nあなたのワンリキーと \nわたしのホームラン、\nこうかんしません?\0",
            "dialog_3": "しばらく ぼくじょうで ポケモンたちを\nかんさつすることにするよ。\0",
            "name_1": "レッドはかせ\0",
            "name_from": "レッドはかせより\0"
        }
    },
    {
        "ja_JP": {
            "dialog_1": "ポケチョリーッス！\nゆっきーなこときのしたゆきなです。\0",
            "exchange_1": "",
            "mail_1": "",
            "mail_2": "ちょーたのしかった！サンキュー!\nまたどこかで あえるといいね！\nP.S.\nこうかんしてくれて ありがとう！\nゆきなのニャース、だいじにしてね。\0",
            "dialog_2": "", "dialog_3": "", "name_1": "", "name_2": "", "pad": ""
        }
    }
]

# Convert dictionary values to a list to maintain legacy sizing logic
en_US_text_list = list(text[3]["en_US"].values())

def get_utf16_len(count):
    return len("".join(en_US_text_list[:count]).encode("utf-16be")) // 2

celebrity = {
    "unknown1": binascii.unhexlify("04ffff00ffff00"),
    "unknown2": binascii.unhexlify("00000000000000000000000000000000000789"),
    "wanted_pokemon": u16(66),
    "celebrity_mii": binascii.unhexlify(mii[1]),
    "celebrity_mii_xmodem": u16(crc16_xmodem(binascii.unhexlify(mii[1]))),
    "celebrity_pokemon": binascii.unhexlify(pokemon[3]),
    "opening_timestamp_1": u32(opening_timestamp + (1209599 * 10)),
    "closing_timestamp_1": u32(opening_timestamp + (1209599 * 11)),
    "unknown_3": u16(0),
    "text_size_section_1": u16(get_utf16_len(1)),
    "text_size_section_2": u16(get_utf16_len(2)),
    "text_size_section_3": u16(get_utf16_len(3)),
}

for i, section in enumerate(en_US_text_list, start=1):
    celebrity[f"celebrity_dialog_{i}"] = section.encode("utf-16be")

celebrity.update({
    "celebrity_dialog_padding": u8(0) * (2048 - get_utf16_len(len(en_US_text_list)) * 2),
    "opening_timestamp_2": u32(opening_timestamp + (1209599 * 8)),
    "closing_timestamp_2": u32(opening_timestamp + (1209599 * 9)),
    "text_size_section_4": u16(get_utf16_len(4)),
    "text_size_section_5": u16(get_utf16_len(5)),
    "unknown_4": u32(0),
    "unknown_5": u32(3060),
    "unknown_6": u32(62),
    "unknown_7": u32(0),
    "unknown_8": u32(0),
    "text_size_section_6": u16(get_utf16_len(6)),
    "text_size_section_7": u16(get_utf16_len(7)),
    "unknown_9": u8(0) * 4248
})

with open("talentzz.dat", "wb") as f:
    for value in celebrity.values():
        f.write(value)

subprocess.run([
    "/usr/bin/python3", "sign_encrypt.py", 
    "-t", "enc", 
    "-in", "talentzz.dat", 
    "-out", "/opt/nwcs/wbm/talent_pt.ja_JP.enc", 
    "-key", "610B782DAD94000572F66AB3AFB6BDEF", 
    "-rsa", "/opt/key/ranch.pem"
], check=True)
