import json
import struct

KNOWN_FIELDS = [
    "Version", "Platform", "FirstPlayStartTicks", "Health", "Level", "LastPerkLevel",
    "Xp", "Karma", "KillCount", "SpentSilverCoins", "HeadshotCount", "Firstblood",
    "KilometersTraveled", "TreasuresDugCount", "SafesOpenedCount", "ActualCityId",
    "ActualLocationId", "ActualQuestId", "ActualQuestState", "LastActualQuestId",
    "LastActualQuestState", "UserName", "NewPlayer", "ClaimedPlayerJourneyMilestoneIds",
    "PlayerJourneyStartingLevel", "SeenPlayerJourneyWhatsNextItemIds",
    "PlayerJourneySeenLevel", "PlayerJourneySeenXp", "MissionRewardCount",
    "CanEscapeQuest", "LastPlayerWeaponSlot", "CoinsGold", "CoinsSilver", "Gas",
    "FreeGasEndTime", "RecievedGoldCoins", "RecievedPerkPoints", "NextItemUId",
    "PlayerEquipment", "PlayerInventoryData", "TrunkInventoryData", "FoundItems",
    "FoundSilverCoins", "FoundGoldCoins", "FoundPassPoints", "WeaponDatas",
    "MiniatureDatas", "VehicleDatas", "RealEstateDatas", "TableDatas",
    "TablesUseServerTime", "BuildingDatas", "TravellingFrom", "TravellingTo",
    "TravellingFromCity", "TravellingToCity", "TravellingPosition",
    "TravellingEncounterId", "TravellingEncounterAvoidProbability",
    "TravellingRunFromQuest", "TravellingEncounterCount", "ActiveCities",
    "VisitedCities", "NewOpenCity", "Skills", "Perks", "FreeSkillsPoints",
    "FreePerksPoints", "SkillCostRecounted", "SeenNewSkills", "KarmaFixed",
    "TalkingCharacterData", "ActiveQuests", "NextDailyQuestsTime",
    "SelectedQuestTab", "SelectedActiveQuestId", "SelectedDoneQuestId",
    "doneUniqueEncounters", "lastEncounters", "AddQuestG1AnalyticsSent",
    "AddQuestWod1AnalyticsSent", "NextGrindLocationVideoTimeTicks",
    "RewardedVideoGroupVideoCount", "RewardedVideoGroupLastVideoTimeSeconds",
    "ShopFreeGasCountdownEndSeconds", "ShopFreeCoinsCountdownEndSeconds",
    "NextLuckyWheelTimeSeconds", "LuckyWheelWatchedVideo",
    "CurrentSurvivalPackCityId", "BoughtSurvivalPackCityIds", "TreasureRoadData",
    "FirstSpecialOffer", "GeneratedFirstActualSpecialOffer", "CheckedForSteamInapp",
    "ActualSpecialOfferCity", "ActualWeaponSpecialOffers",
    "ActualOldWeaponSpecialOffers", "ActualArmorSpecialOffer",
    "ActualTwoItemsSpecialOffer", "ActualOneItemSpecialOffer",
    "ActualOneItemSpecialOffer2", "ActualVehicleSpecialOffer",
    "ActualSlayerSpecialOffer", "ActualMissionSpecialOffer",
    "ActualAllBoosterSpecialOffer", "JustBoughtSpecialOffer",
    "PendingSpecialOfferPurchases", "RecievedSpecialOffers",
    "BoughtSpecialOfferIds", "RealMoneySpent", "WeaponSpecialOffer",
    "ArmorSpecialOffer", "TwoItemsSpecialOffer", "OneItemSpecialOffer",
    "OneItemSpecialOffer2", "BoughtWeaponSpecialOfferConfigs",
    "BoughtArmorSpecialOfferConfigs", "JustBoughtWeaponSpecialOffer",
    "JustBoughtArmorSpecialOffer", "JustBoughtTwoItemsSpecialOffer",
    "JustBoughtOneItemSpecialOffer", "JustBoughtOneItemSpecialOffer2",
    "ShowBestValuePackOffer", "SendShopTabsAnalytics", "LastSeenLevel",
    "PickedUniqueItems", "PickedWeaponId", "PickedMeleeWeaponId",
    "UsedMedical", "GotPlayersJourneyReward", "PlayedCircuitMiniGame",
    "MiniatureData", "ZombiePassData", "LastZombiePassWeaponReward",
    "Boosts", "SourceBoosts", "AdsEnabled", "NoAdsEndTime",
    "LimitedNoAdsEndTime", "DailyPackShowTime", "BiggerBackpackCount",
    "BiggerTrunkCount", "HasChuckNorrisPack", "HasSchwarzeneggerPack",
    "HasRamboPack", "HasBruceLeePack", "HasSupermanPack", "HasSteamDlc",
    "BiggerGasTankCount", "DoneTutorialTasks", "HasReloaded",
    "HasClickedOnQuest", "CouponeCodes", "OutOfBoundaries",
    "BoundariesGoldValue", "WeaponUpgradeSystemType", "SpecialOfferWeaponFix",
    "PlayerPassedIntroQuest", "WoodlandsIntro", "GameProgressSave",
    "BoolValues", "LastInAppReviewShowTimeSeconds", "OfferwallTotalRewardSet",
    "OfferwallTotalReward", "OfferwallRewardSum", "MissionRewardLastClaimed",
    "MissionRewardShowCount", "MissionRewardClaimCount",
]

def extract_json_blocks(raw_bytes):
    text = raw_bytes.decode("latin1")
    items = []
    depth = 0
    start = None
    in_str = False
    esc = False
    for i, ch in enumerate(text):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch in ("{", "["):
                if depth == 0:
                    start = i
                depth += 1
            elif ch in ("}", "]"):
                if depth > 0:
                    depth -= 1
                    if depth == 0 and start is not None:
                        snippet = text[start : i + 1]
                        try:
                            items.append(json.loads(snippet))
                        except json.JSONDecodeError:
                            pass
                        start = None
    return items

def decode_value(raw):
    base_meta = {"raw_hex": raw.hex()}
    if not raw:
        return None, {**base_meta, "mode": "empty", "orig_val": None}

    tag = raw[0]

    # Tag 0x07: 4-byte little-endian int32 (+ optional trailing byte)
    if tag == 0x07 and len(raw) >= 5:
        val = struct.unpack_from("<i", raw, 1)[0]
        return val, {**base_meta, "mode": "tag07_i32", "tail_hex": raw[5:].hex(), "orig_val": val}

    # Tag 0x04: 4-byte little-endian int32 (+ optional trailing byte)
    if tag == 0x04 and len(raw) >= 5:
        val = struct.unpack_from("<i", raw, 1)[0]
        return val, {**base_meta, "mode": "tag04_i32", "tail_hex": raw[5:].hex(), "orig_val": val}

    # Tag 0x06: 4-byte little-endian float32 (+ optional trailing byte)
    if tag == 0x06 and len(raw) >= 5:
        val = round(struct.unpack_from("<f", raw, 1)[0], 6)
        return val, {**base_meta, "mode": "tag06_f32", "tail_hex": raw[5:].hex(), "orig_val": val}

    # Tag 0x02: bool (+ optional trailing byte)
    if tag == 0x02 and len(raw) >= 2:
        val = bool(raw[1])
        return val, {**base_meta, "mode": "tag02_bool", "tail_hex": raw[2:].hex(), "orig_val": val}

    # Tag 0x08: 8-byte little-endian int64 (+ optional trailing byte)
    if tag == 0x08 and len(raw) >= 9:
        val = struct.unpack_from("<q", raw, 1)[0]
        return val, {**base_meta, "mode": "tag08_i64", "tail_hex": raw[9:].hex(), "orig_val": val}

    # Tag 0x0d or 0x09: 1-byte length + UTF-8 string (+ optional JSON blocks after it)
    if tag in (0x0D, 0x09) and len(raw) >= 2:
        slen = raw[1]
        if 2 + slen <= len(raw):
            sbytes = raw[2 : 2 + slen]
            try:
                stext = sbytes.decode("utf-8")
                if all(c.isprintable() or c in "\r\n\t" for c in stext):
                    tail = raw[2 + slen :]
                    json_blocks = extract_json_blocks(tail)
                    if json_blocks:
                        out_val = {
                            "type_name": stext,
                            "items": json_blocks if len(json_blocks) > 1 else json_blocks[0],
                        }
                        return out_val, {**base_meta, "mode": "tagged_type_json", "orig_val": out_val}
                    return stext, {
                        **base_meta,
                        "mode": f"tag{tag:02x}_str1",
                        "tail_hex": tail.hex(),
                        "orig_val": stext,
                    }
            except UnicodeDecodeError:
                pass

    # Embedded JSON object(s) or array(s)
    json_blocks = extract_json_blocks(raw)
    if json_blocks:
        parsed_out = json_blocks[0] if len(json_blocks) == 1 else json_blocks
        return parsed_out, {**base_meta, "mode": "json_verbatim", "orig_val": parsed_out}

    # Untagged 6-byte big-endian integer (e.g. BiggerGasTankCount: 000000000011 -> 17)
    if len(raw) == 6 and raw[:4] == b"\x00\x00\x00\x00":
        val = int.from_bytes(raw, "big")
        return val, {**base_meta, "mode": "u48_be", "orig_val": val}

    hex_str = raw.hex()
    return hex_str, {**base_meta, "mode": "raw_hex", "orig_val": hex_str}

def parse_save(plain_bytes):
    positions = []
    search_from = 0
    for name in KNOWN_FIELDS:
        idx = plain_bytes.find(name.encode("utf-8"), search_from)
        if idx != -1:
            positions.append((idx, name))
            search_from = idx + len(name)

    header = plain_bytes[: positions[0][0]] if positions else b""
    data = {}
    fields_meta = {}
    order = []

    for i, (pos, name) in enumerate(positions):
        end = positions[i + 1][0] if i + 1 < len(positions) else len(plain_bytes)
        raw_chunk = plain_bytes[pos + len(name) : end]
        val, finfo = decode_value(raw_chunk)
        data[name] = val
        fields_meta[name] = finfo
        order.append(name)

    return {
        "_meta": {
            "header_hex": header.hex(),
            "order": order,
            "fields": fields_meta,
        },
        "data": data,
    }

if __name__ == "__main__":
    with open("save_decrypted.json", "rb") as f:
        plain = f.read()

    clean = parse_save(plain)
    with open("save_clean.json", "w", encoding="utf-8") as out:
        json.dump(clean, out, indent=2, ensure_ascii=False)

    d = clean["data"]
    m = clean["_meta"]["fields"]
    print(f"Wrote {len(d)} fields to save_clean.json")
    for k in (
        "UserName", "Level", "Xp", "CoinsGold", "CoinsSilver",
        "Health", "Karma", "BiggerGasTankCount", "Gas",
        "FreeSkillsPoints", "FreePerksPoints", "NoAdsEndTime",
    ):
        if k in d:
            print(f"  {k:20s}: {d[k]!r} ({m[k]['mode']})")
