import subprocess
import struct
import binascii
import calendar
import datetime


def u8(data):
    if not 0 <= data <= 255:
        log("u8 out of range: %s" % data, "INFO")
        data = 0
    return struct.pack(">B", data)


def u16(data):
    if not 0 <= data <= 65535:
        log("u16 out of range: %s" % data, "INFO")
        data = 0
    return struct.pack(">H", data)


def u32(data):
    if not 0 <= data <= 4294967295:
        log("u32 out of range: %s" % data, "INFO")
        data = 0
    return struct.pack(">I", data)

CRC16_XMODEM_TABLE = [
        0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
        0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
        0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
        0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
        0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
        0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
        0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
        0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
        0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
        0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
        0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
        0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
        0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
        0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
        0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
        0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
        0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
        0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
        0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
        0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
        0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
        0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
        0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
        0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
        0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
        0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
        0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
        0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
        0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
        0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
        0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
        0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0,
        ]


def _crc16(data, crc, table):
    """Calculate CRC16 using the given table.
    `data`      - data for calculating CRC, must be a string
    `crc`       - initial value
    `table`     - table for caclulating CRC (list of 256 integers)
    Return calculated value of CRC
    """
    for byte in data:
        crc = ((crc<<8)&0xff00) ^ table[((crc>>8)&0xff)^ord(chr(byte))]
    return crc & 0xffff


def crc16(data, crc=0):
    """Calculate CRC-CCITT (XModem) variant of CRC16.
    `data`      - data for calculating CRC, must be a string
    `crc`       - initial value
    Return calculated value of CRC
    """
    return _crc16(data, crc, CRC16_XMODEM_TABLE)

opening_timestamp = (
    int(calendar.timegm(datetime.datetime.utcnow().timetuple())) - 946684800
)
# dialog_1
# exchange_1
# mail_1
# mail_2
# dialog_2
# dialog_3

pokemon = ["", "", "", "B0514907000012EA03E2243BA248E7DFBF81BE3F675769D38AAD942D08CE6CA89805E09F446BE7007525F0A541CB06E1FFDB3127A010751CEE6D53D48F5EE88E66FA13015A32250546496302F6AD8CECAB6AEE96F0E5CEB37253D7F8C8BD8C9DA8D7B1C180E361A11B1496F56510A40B9DB7958DEED9015E532E6F482F0AEBF246353B24838D8766", ""]

mii = ["80060041006B006900790061006D006100000000000040408836A1113A017D6284003E00017D0891A48B084084485AAE008A008A25040000000000000000000000000000000000000000", "8008004200610062006100690067006F006E0000000040408836A0223A017D6240004400017D06A2684C08608640784E008A008A25040000000000000000000000000000000000000000", "80160047006F006C006B006F00000000000000000000404088369F123A017D6284002E00613D08611CAA0640743020CE008A402625040000000000000000000000000000000000000000", "000230EC30C330C9306F304B305B00000000000000007F408108E2EFC2EFA02E44C43E00918008737C890460333030EC8280028A25040000000000000000000000000000000000000000", "C00E00590075006B0069006E0061000000000000000040408836A0623A017D6220008F8001BD24A38C6B06A06438B0AD008A008A8C580000000000000000000000000000000000000000"]

text = [
    {
        "ja_JP": [
            "ポケモーニング！" + "\n" +
            "あきやまたいいんだよ" + "\0",

            "コイキングをつれてくると、ケッキングと" + "\n" +
            "こうかんしてくれるそうです。" + "\0",

            "",

            "",

            "",

            "",

            "",

            "",

            "",
        ]
    },
    {
        "ja_JP": [
            "",

            "すこい！ムックルをつれてきて" + "\n" +
            "さっそくこうかんしよう。" + "\0",

            "",

            "",

            "",

            "",

            "",

            "",

            "",
        ]
    },
    {
        "ja_JP": [
            "やあみんな、ポケサンカンパニーの" + "\n" +
            "ゴルゴしょちょうだ。" + "\n" +
            "ポケモン★サンデーをみて、もっと" + "\n" +
            "ポケモンをすきになってくれよな。" + "
                                                  ",
            "じつはな、ジグサクマを" + "\n" +
            "25ひきあつめると" + "\n" +
            "ジグザグパレードをするんじゃ。" + "\n" +
            "わしは、と〜ってもそれがみたい！" + "\0",

            "ぜひ、キミの ジグサグマと" + "\n" +
            "わしの オクタンを" + "\n" +
            "こうかんしようじゃないか。" + "\0",

            "たのしかった!" + "\n" +
            "ほんとにありがとう。" + "\n" +
            "このなつは、" + "\n" +
            "えいがかんで あおうね！" + "\0",

            "",

            "わしは、しばらくほくじょうで" + "\n" +
            "あそんでいくぞ。いいな？" + "\0",

            "ジグザグマをつれてくると" + "\n" +
            "オクタンと" + "\n" +
            "こうかんしてくれるそうです。" + "\0",

            "お、ジグザグマを" + "\n" +
            "つれてきてくれたのかい。" + "\n" +
            "さっそく こうかんしょうじゃないか。" + "\0",

            "ゴルゴしょちょう" + "\0",

            "",
        ]
    },
    {
        "en_US": [
            "PokéMorning!" + "\n" +
            "Did you happen to see me on Pokémon Sunday?" + "\n" +
            "I'm Professor Red!" + "
                                    " +
            "I brought my METAGROSS, Homerun!" + "\0",

            "Oh, that's MACHOP!" + "\n" +
            "You brought it for me, right?" + "\n" +
            "Thank you." + "\n" +
            "So, let's trade." + "\0",

            "I have to return to" + "\n",
            "the PokéSun Company soon..." + "\n" +
            "Let's meet again on Pokémon Sunday!" + "\n" +
            "Poké we.. GO!" + "\0",

            "P.S." + "\n" +
            "Thank you for trading for METAGROSS." + "\n" +
            "My Homerun is really strong~!" + "\n" +
            "Please take good care of it!" + "\0",

            "Well, actually, I heard an amazing" + "\n" +
            "rumor that if you " + "\n" +
            "gather 8 Fighting Type Pokémon in the new ranch," + "\n" +
            "they'll have a Tournament" + "
                                           ",
            "I wonder, would you trade your MACHOP for my Homerun?" + "\0",

            "I'm going to watch the Pokémon on the ranch for a while." + "\0",

            "Professor Red" + "\0",

            "From Professor Red" + "\0",
        ],
        "ja_JP": [
            "ポケモーニング!" + "\n" +
            "「ポケモン☆サンデー」での わたしの" + "\n" +
            "かつやくを みてくれているかな?" + "\n" +
            "レッドはかせです!" + "
                                   " +
            "わたしのメタグロス、ホームランを" + "\n" +
            "つれてきちゃいました～!" + "\0",

            "お、それはワンリキー!" + "\n" +
            "つれてきてくれたんですね。" + "\n" +
            "ありがとう。" + "\n" +
            "では、こうかんしましょうか。" + "\0",

            "そろそろ ポケサンカンパニーに " + "\r\n" +
            "かえらなくては……" + "\r\n" +
            "また 「ポケモン☆サンデー」で" + "\r\n" +
            "あいましょう!" + "\r\n" +
            "ポケ・ウィー・ゴー!" + "\0",

            "P.S." + "\r\n" +
            "メタグロスと" + "\r\n" +
            "こうかんしてくれて、ありがとう。" + "\r\n" +
            "わたしの ホームランは" + "\r\n" +
            "つよいですよ～!" + "\r\n" +
            "ちゃんと かわいがってくださいね!" + "\0",

            "いや～、じつはですね、すごいウワサを " + "\n" +
            "みみにしたんですが、" + "
                                      " +
            "あたらしいぼくじょうで、" + "\n" +
            "かくとうタイプの ポケモンを 8ぴき " + "\n" +
            "あつめると、トーナメントを " + "\n" +
            "するらしいんですよね～。" + "
                                          " +
            "すっごく きになってるんですが、 " + "\n" +
            "あなたのワンリキーと " + "\n" +
            "わたしのホームラン、" + "\n" +
            "こうかんしません?" + "\0",

            "しばらく ぼくじょうで ポケモンたちを" + "\n" +
            "かんさつすることにするよ。" + "\0",

            "レッドはかせ" + "\0",

            "レッドはかせより" + "\0",
        ],
    },
    {
        "ja_JP": [
            "ポケチョリーッス！" + "\n" +
            "ゆっきーなこときのしたゆきなです。" + "\0",

            "",

            "",

            "ちょーたのしかった！サンキュー!" + "\n" +
            "またどこかで あえるといいね！" + "\n" +
            "P.S." + "\n" +
            "こうかんしてくれて ありがとう！" + "\n" +
            "ゆきなのニャース、だいじにしてね。" + "\0",

            "",

            "",

            "",

            "",

            "",
        ]
    }
]

celebrity = {}

celebrity["unknown1"] = binascii.unhexlify("04ffff00ffff00")
celebrity["unknown2"] = binascii.unhexlify("00000000000000000000000000000000000789")
celebrity["wanted_pokemon"] = u16(66)
celebrity["celebrity_mii"] = binascii.unhexlify(mii[1])
celebrity["celebrity_mii_xmodem"] = u16(crc16(binascii.unhexlify(mii[1])))
celebrity["celebrity_pokemon"] = binascii.unhexlify(pokemon[3])
celebrity["opening_timestamp_1"] = u32(opening_timestamp + (1209599 * 10))
celebrity["closing_timestamp_1"] = u32(opening_timestamp + (1209599 * 11))
celebrity["unknown_3"] = u16(0)
celebrity["text_size_section_1"] = u16(
    int(len(text[3]["en_US"][0].encode("utf-16be")) / 2)
)
celebrity["text_size_section_2"] = u16(
    int(len("".join(text[3]["en_US"][:2]).encode("utf-16be")) / 2)
)
celebrity["text_size_section_3"] = u16(
    int(len("".join(text[3]["en_US"][:3]).encode("utf-16be")) / 2)
)

i = 1

for section in text[3]["en_US"]:
    celebrity["celebrity_dialog_" + str(i)] = section.encode("utf-16be")
    i += 1

celebrity["celebrity_dialog_padding"] = u8(0) * (
    2048 - int(len("".join(text[3]["en_US"]).encode("utf-16be")))
)

celebrity["opening_timestamp_2"] = u32(opening_timestamp + (1209599 * 8))
celebrity["closing_timestamp_2"] = u32(opening_timestamp + (1209599 * 9))
celebrity["text_size_section_4"] = u16(
    int(len("".join(text[3]["en_US"][:4]).encode("utf-16be")) / 2)
)
celebrity["text_size_section_5"] = u16(
    int(len("".join(text[3]["en_US"][:5]).encode("utf-16be")) / 2)
)
celebrity["unknown_4"] = u32(0)
celebrity["unknown_5"] = u32(3060)
celebrity["unknown_6"] = u32(62)
celebrity["unknown_7"] = u32(0)
celebrity["unknown_8"] = u32(0)
celebrity["text_size_section_6"] = u16(
    int(len("".join(text[3]["en_US"][:6]).encode("utf-16be")) / 2)
)
celebrity["text_size_section_7"] = u16(
    int(len("".join(text[3]["en_US"][:7]).encode("utf-16be")) / 2)
)

celebrity["unknown_9"] = u8(0) * 4248

with open("talentzz.dat", "wb") as f:
    for value in celebrity.values():
        f.write(value)

subprocess.call(["/usr/bin/python3", "sign_encrypt.py", "-t", "enc", "-in", "talentzz.dat", "-out", "/opt/nwcs/wbm/talent_pt.ja_JP.enc", "-key", "610B782DAD94000572F66AB3AFB6BDEF", "-rsa", "/opt/key/pkmndungeon.pem"])
