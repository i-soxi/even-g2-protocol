import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), "pbgenerated/g2"))
import pandas as pd
from dataclasses import dataclass
from typing import Any, Optional
from enum import Enum
import struct

from dev_config_protocol_pb2 import DevCfgDataPackage
from notification_pb2 import NotificationDataPackage
from even_ai_pb2 import EvenAIDataPackage
from dashboard_pb2 import DashboardDataPackage
from transcribe_pb2 import TranscribeDataPackage
from translate_pb2 import TranslateDataPackage
from teleprompt_pb2 import TelepromptDataPackage
from navigation_pb2 import navigation_main_msg_ctx
from g2_setting_pb2 import G2SettingPackage
from conversate_pb2 import ConversateDataPackage
from quicklist_pb2 import QuicklistDataPackage
from sync_info_pb2 import sync_info_main_msg_ctx
from health_pb2 import HealthDataPackage
from logger_pb2 import logger_main_msg_ctx
from glasses_case_pb2 import GlassesCaseDataPackage
from module_configure_pb2 import module_configure_main_msg_ctx
from onboarding_pb2 import OnboardingDataPackage
from ring_pb2 import RingDataPackage


from efs_transmit_pb2 import *


# This defines the list of diffrent potential service ids
class ServiceID:
    UI_LOGGER_APP_ID = 0xf
    UX_RING_DATA_RELAY_ID = 0x91
    UI_ONBOARDING_APP_ID = 0x10
    SERVICE_MODULE_CONFIGURE_APP_ID = 0x20
    UX_GLASSES_CASE_APP_ID = 0x81
    UI_HEALTH_APP_ID = 0xe
    SERVICE_SYNC_INFO_APP_ID = 0xd
    UI_QUICKLIST_APP_ID = 0xc
    UI_SETTING_APP_ID = 0x9
    UI_BACKGROUND_NAVIGATION_ID = 0x8
    UI_TELEPROMPT_APP_ID = 0x6
    UI_TRANSCRIBE_APP_ID = 0xa
    UI_TRANSLATE_APP_ID = 0x5
    UI_FOREGROUND_EVEN_AI_ID = 0x7
    UI_FOREGROUND_NOTIFICATION_ID = 0x4
    UX_DEVICE_SETTINGS_APP_ID = 0x80
    UI_CONVERSATE_APP_ID = 0xb
    UI_BACKGROUND_DASHBOARD_APP_ID = 0x1
    UX_EVEN_FILE_SERVICE_RAW_SEND_DATA_ID = 0xc5
    UX_EVEN_FILE_SERVICE_CMD_EXPORT_ID = 0xc6
    UX_EVEN_FILE_SERVICE_CMD_SEND_ID = 0xc4
    UX_OTA_TRANSMIT_CMD_ID = 0xc0
    UX_OTA_TRANSMIT_RAW_DATA_ID = 0xc1
    INVALID_SERVICE_ID = 0xff
    UX_EVEN_FILE_SERVICE_RAW_EXPORT_DATA_ID = 0xc7
    UX_OTA_EXPORT_FILE_RAW_DATA_ID = 0xc3
    UX_OTA_EXPORT_FILE_CMD_ID = 0xc3
    UX_RING_ROW_DATA_ID = 0x90
    UI_FOREGROUND_SYSTEM_ALERT_APP_ID = 0x21
    UI_FOREGROUND_MEUN_ID = 0x3
    UI_DEFAULT_APP_ID = 0x0


# for common commands, this defines the handler protobuf class to use for decoding
service_id_class_mapping = {
    ServiceID.UX_DEVICE_SETTINGS_APP_ID : DevCfgDataPackage,
    ServiceID.UI_BACKGROUND_DASHBOARD_APP_ID : DashboardDataPackage,
    ServiceID.UI_FOREGROUND_NOTIFICATION_ID : NotificationDataPackage,
    ServiceID.UI_FOREGROUND_EVEN_AI_ID : EvenAIDataPackage,
    ServiceID.UI_TRANSCRIBE_APP_ID : TranscribeDataPackage,
    ServiceID.UI_TRANSLATE_APP_ID : TranslateDataPackage,
    ServiceID.UI_TELEPROMPT_APP_ID : TelepromptDataPackage,
    ServiceID.UI_BACKGROUND_NAVIGATION_ID : navigation_main_msg_ctx,
    ServiceID.UI_SETTING_APP_ID : G2SettingPackage,
    ServiceID.UI_CONVERSATE_APP_ID : ConversateDataPackage,
    ServiceID.UI_QUICKLIST_APP_ID : QuicklistDataPackage,
    ServiceID.SERVICE_SYNC_INFO_APP_ID : sync_info_main_msg_ctx,
    ServiceID.UI_HEALTH_APP_ID : HealthDataPackage,
    ServiceID.UI_LOGGER_APP_ID : logger_main_msg_ctx,
    ServiceID.UX_GLASSES_CASE_APP_ID : GlassesCaseDataPackage,
    ServiceID.SERVICE_MODULE_CONFIGURE_APP_ID : module_configure_main_msg_ctx,
    ServiceID.UI_ONBOARDING_APP_ID : OnboardingDataPackage,
    ServiceID.UX_RING_DATA_RELAY_ID : RingDataPackage,
    ServiceID.UX_RING_ROW_DATA_ID: RingDataPackage,
}

# printable string for each service id - @TODO: should convert all this to use Enum so we get it auto
service_name_mapping = {
    ServiceID.UI_LOGGER_APP_ID:"UI_LOGGER_APP_ID",
    ServiceID.UX_RING_DATA_RELAY_ID:"UX_RING_DATA_RELAY_ID",
    ServiceID.UI_ONBOARDING_APP_ID:"UI_ONBOARDING_APP_ID",
    ServiceID.SERVICE_MODULE_CONFIGURE_APP_ID:"SERVICE_MODULE_CONFIGURE_APP_ID",
    ServiceID.UX_GLASSES_CASE_APP_ID:"UX_GLASSES_CASE_APP_ID",
    ServiceID.UI_HEALTH_APP_ID:"UI_HEALTH_APP_ID",
    ServiceID.SERVICE_SYNC_INFO_APP_ID:"SERVICE_SYNC_INFO_APP_ID",
    ServiceID.UI_QUICKLIST_APP_ID:"UI_QUICKLIST_APP_ID",
    ServiceID.UI_SETTING_APP_ID:"UI_SETTING_APP_ID",
    ServiceID.UI_BACKGROUND_NAVIGATION_ID:"UI_BACKGROUND_NAVIGATION_ID",
    ServiceID.UI_TELEPROMPT_APP_ID:"UI_TELEPROMPT_APP_ID",
    ServiceID.UI_TRANSCRIBE_APP_ID:"UI_TRANSCRIBE_APP_ID",
    ServiceID.UI_TRANSLATE_APP_ID:"UI_TRANSLATE_APP_ID",
    ServiceID.UI_FOREGROUND_EVEN_AI_ID:"UI_FOREGROUND_EVEN_AI_ID",
    ServiceID.UI_FOREGROUND_NOTIFICATION_ID:"UI_FOREGROUND_NOTIFICATION_ID",
    ServiceID.UX_DEVICE_SETTINGS_APP_ID:"UX_DEVICE_SETTINGS_APP_ID",
    ServiceID.UI_CONVERSATE_APP_ID:"UI_CONVERSATE_APP_ID",
    ServiceID.UI_BACKGROUND_DASHBOARD_APP_ID:"UI_BACKGROUND_DASHBOARD_APP_ID",
    ServiceID.UX_EVEN_FILE_SERVICE_RAW_SEND_DATA_ID:"UX_EVEN_FILE_SERVICE_RAW_SEND_DATA_ID",
    ServiceID.UX_EVEN_FILE_SERVICE_CMD_EXPORT_ID:"UX_EVEN_FILE_SERVICE_CMD_EXPORT_ID",
    ServiceID.UX_EVEN_FILE_SERVICE_CMD_SEND_ID:"UX_EVEN_FILE_SERVICE_CMD_SEND_ID",
    ServiceID.UX_OTA_TRANSMIT_CMD_ID:"UX_OTA_TRANSMIT_CMD_ID",
    ServiceID.UX_OTA_TRANSMIT_RAW_DATA_ID:"UX_OTA_TRANSMIT_RAW_DATA_ID",
    ServiceID.INVALID_SERVICE_ID:"INVALID_SERVICE_ID",
    ServiceID.UX_EVEN_FILE_SERVICE_RAW_EXPORT_DATA_ID:"UX_EVEN_FILE_SERVICE_RAW_EXPORT_DATA_ID",
    ServiceID.UX_OTA_EXPORT_FILE_RAW_DATA_ID:"UX_OTA_EXPORT_FILE_RAW_DATA_ID",
    ServiceID.UX_OTA_EXPORT_FILE_CMD_ID:"UX_OTA_EXPORT_FILE_CMD_ID",
    ServiceID.UX_RING_ROW_DATA_ID:"UX_RING_ROW_DATA_ID",
    ServiceID.UI_FOREGROUND_SYSTEM_ALERT_APP_ID:"UI_FOREGROUND_SYSTEM_ALERT_APP_ID",
    ServiceID.UI_FOREGROUND_MEUN_ID:"UI_FOREGROUND_MEUN_ID",
    ServiceID.UI_DEFAULT_APP_ID:"UI_DEFAULT_APP_ID",
}



# utility functions - crc16 for packets
def calc_crc(data):
    crcAccum = 0xFFFF
    for i in range(len(data)):
        crcAccum = ((crcAccum >> 8) | ((crcAccum << 8) & 0xFF00)) ^ data[i]
        crcAccum ^= (crcAccum & 0xFF) >> 4
        crcAccum ^= (crcAccum << 12) & 0xFFFF
        crcAccum ^= ((crcAccum & 0xFF) << 5) & 0xFFFF

    computed = crcAccum & 0xFFFF
    return computed



## crc 32 used for file data
CRC_32_TABLE = [0, 0x1edc6f41, 0x3db8de82, 0x2364b1c3,
		2071051524, 1705890373, 1187603334, 1477774535,
		4142103048, 3896448329, 3411780746, 3582446539,
		2375206668, 2471405645, 2955549070, 2935387855,
		4078607185, 3989238800, 3466741203, 3497929362,
		2288723541, 2528594196, 3050567895, 2869925782,
		0x5f9e159, 0x1b258e18, 0x38413fdb, 0x269d509a,
		2122865757, 1616130844, 1127252703, 1575808414,
		4176042467, 3862247074, 3310454625, 3683510304,
		2207835367, 2638515110, 3189783141, 2700891428,
		0xe0a23eb, 0x10d64caa, 0x33b2fd69, 0x2d6e9228,
		1971035887, 1806168494, 1220755565, 1444884268,
		0xbf3c2b2, 0x152fadf3, 0x364b1c30, 0x28977371,
		1887600566, 1851658487, 1295687988, 1407635061,
		4245731514, 3821852667, 3232261688, 3732146553,
		2254505406, 2562550527, 3151616828, 2768614525,
		4010728583, 4057117638, 3535143429, 3429526852,
		2491376003, 2325941954, 2848440065, 3072053312,
		0x19eda68f, 0x731c9ce, 0x2455780d, 0x3a89174c,
		1654397835, 2084598986, 1596245257, 1106815560,
		0x1c1447d6, 0x2c82897, 0x21ac9954, 0x3f70f615,
		1734736594, 2042205587, 1524442192, 1140935441,
		3942071774, 4096479903, 3612336988, 3381890077,
		2441511130, 2405101467, 2889768536, 3001168153,
		0x17e78564, 0x93bea25, 0x2a5f5be6, 0x348334a7,
		1821784160, 1917474593, 1362028258, 1341295011,
		3775201132, 4292382765, 3703316974, 3261091503,
		2591375976, 2225679657, 2815270122, 3104961451,
		3841793589, 4196495732, 3645227191, 3348738038,
		2676794161, 2169556080, 2721349043, 3169325810,
		0x121e643d, 0xcc20b7c, 0x2fa6babf, 0x317ad5fe,
		1768937785, 2008266360, 1423378363, 1242261754,
		3233928783, 3726489870, 4252567757, 3819267980,
		3148901195, 2775319562, 2248717769, 2564086408,
		0x3622ac47, 0x28fec306, 0xb9a72c5, 0x15461d84,
		1297289539, 1401912834, 1894502337, 1849139328,
		0x33db4d1e, 0x2d07225f, 0xe63939c, 0x10bffcdd,
		1219162138, 1450614619, 1964125848, 1808679385,
		3308795670, 3689175127, 4169197972, 3864823509,
		3192490514, 2694178131, 2213631120, 2636987345,
		0x38288fac, 0x26f4e0ed, 0x590512e, 0x1b4c3e6f,
		1129919144, 1569021417, 2128735274, 1614644075,
		3469473188, 3491207909, 4084411174, 3987686503,
		3048884384, 2875598817, 2281870882, 2531195235,
		3409057021, 3589176252, 4136290943, 3897992510,
		2957224441, 2929706680, 2382067579, 2468812858,
		0x3dd16ef5, 0x230d01b4, 0x69b077, 0x1eb5df36,
		1184945137, 1484569776, 2065173875, 1707369010,
		0x2fcf0ac8, 0x31136589, 0x1277d44a, 0xcabbb0b,
		1421785036, 1247991949, 1762027854, 2010777103,
		3643568320, 3354402689, 3834949186, 4199072003,
		2724056516, 3162612357, 2682590022, 2168028167,
		3704983961, 3255434968, 3782037275, 4289798234,
		2812554397, 3111666652, 2585588255, 2227215710,
		0x2a36eb91, 0x34ea84d0, 0x178e3513, 0x9525a52,
		1363629717, 1335572948, 1828685847, 1914955606,
		3609613099, 3388619882, 3936259497, 4098024168,
		2891443759, 2995487086, 2448371885, 2402508780,
		0x21c52923, 0x3f194662, 0x1c7df7a1, 0x2a198e0,
		1521783847, 1147730790, 1728858789, 2043684324,
		0x243cc87a, 0x3ae0a73b, 0x198416f8, 0x75879b9,
		1598911870, 1100028479, 1660267516, 2083112125,
		3537875570, 3422805299, 4016532720, 4055565233,
		2846756726, 3077726263, 2484523508, 2328542901]


assert len(CRC_32_TABLE) == 256

def calc_crc_32(data: bytes | bytearray | memoryview) -> int:
    """
      crc starts at 0
      for each byte b:
        idx = b XOR (crc >> 24)
        crc = ((crc << 8) & 0xffffffff) XOR TABLE[idx]
    Returns crc as a Python int in [0, 2**32-1].
    """
    mv = data if isinstance(data, memoryview) else memoryview(data)
    crc = 0
    for b in mv:
        idx = b ^ ((crc >> 24) & 0xFF)
        crc = ((crc << 8) & 0xFFFFFFFF) ^ (CRC_32_TABLE[idx] & 0xFFFFFFFF)
    return crc





class BleDataPackage:
    """Main parsing class for the protobuf based command messages.

        fromServiceId will, given a serviceId and payload, determine which class to parse
        based on serviceId and then parse the actual message and return it, otherwise None
        if something fails or there is no handler defined for it
    """
    @staticmethod
    def fromServiceId(serviceId, payload):
        if not payload:
            out = BleDataPackage()
            out.serviceId = serviceId
            return out

        name = service_name_mapping.get(serviceId, None)
        if name is None:
            assert False
            print("    SERVICE NOT FOUND: ", hex(serviceId))
        else:
            print("     Service=", name)
            service_msg_class = service_id_class_mapping.get(serviceId, None)
            if service_msg_class is not None:
                data = service_msg_class()
                try:
                    data.ParseFromString(payload)
                    return data
                except Exception as e:
                    print("Error parsing: ", e)
            else:
                print("    Service found but has no handler: ", hex(serviceId))





## outer Transport header class that is put as a header on any packet
@dataclass
class EvenBleTransport:
    """Transport header class that is used as the header on all packets sent with the glases

        fromBytes will decode a raw packet payload into header fields and a sub payload of the
        actual message
    """
    sourceId: int
    destinationId: int
    syncId: int
    packetTotalNum: int
    packetSerialNum: int
    serviceId: int
    notify: bool
    reserveFlag: bool
    reserve: int
    resultCode: int
    payload: bytes
    crc: Optional[int]




    def verifyCrc(self) -> bool:
        computed = calc_crc(self.payload)
        return computed == self.crc

    @staticmethod
    def fromBytes(data_bytes: bytes):

        # header:
        #   0 - fixed id 0xaa
        #   1 - src + dest (in bottom + top 4 bits )
        #   2 - syncId - unique value that stays constant across a multipart packet seq
        #   3 - payloadLen
        #   4 - packetTotalNum
        #   5 - packetSerialNum?
        #   6 - serviceId ?
        #   7 - status? (notify, resultcode, etc)


        # Minimum BLE frame length check.
        data_len = len(data_bytes)
        if data_len < 8:
            print("    !!!!!!Data too short")
            return None

        # check that we have a proper start byte
        header = int(data_bytes[0])
        if header != 0xAA:
            print("    !!!!!!Header was not 0xAA")
            return None

        byte1 = int(data_bytes[1])
        sourceId = byte1 & 0x0F
        destinationId = (byte1 >> 4) & 0x0F
        syncId = int(data_bytes[2])
        payloadLen = int(data_bytes[3])


        # validate that the packet len is what we expect
        expectLen = payloadLen + 8 # header has 8 bytes    #### LEN is good
        if data_len < expectLen:
            print("    !!!!!!Message header length did not match data lenght")
            return None


        packetTotalNum = int(data_bytes[4])
        packetSerialNum = int(data_bytes[5])
        serviceId = int(data_bytes[6])
        status = int(data_bytes[7])


        notify = (status & 0x01) != 0
        resultCode = (status >> 1) & 0x0F
        reserveFlag = (status & 0x20) != 0 # bit-5 flag
        reserve = (status >> 6) & 0x03 # upper 2 bits

        crc = None

        # check crc if this is the last packet and there is a crc present
        if resultCode == 0:
            hasTrailingCrc = packetSerialNum == packetTotalNum
            payloadEnd = payloadLen + 8 - (2 if hasTrailingCrc else 0)
            payload = data_bytes[8:payloadEnd]
            if hasTrailingCrc:
                crcLo = data_bytes[payloadEnd]
                crcHi = data_bytes[payloadEnd+1]
                crc = (crcHi << 8) | crcLo

        else:
            payload = None
            crc = None

        return EvenBleTransport(
            sourceId=sourceId,
            destinationId=destinationId,
            syncId=syncId,
            packetTotalNum=packetTotalNum,
            packetSerialNum=packetSerialNum,
            serviceId=serviceId,
            notify=notify,
            reserveFlag=reserveFlag,
            reserve=reserve,
            resultCode=resultCode,
            payload=payload,
            crc=crc
        )



    def dataPackage(self):
        """Try to parse a protobuf message for the main payload and return it"""
        sid = self.serviceId
        return BleDataPackage.fromServiceId(sid, self.payload)






# handler class to parse transport and route to the proper service (either common or file for now -
#  in the real version, there is also an ota service and stream handling)
class MsgHandler:
    def __init__(self):
        self.partials = {}
        self.failed_msgs = {}


    def handleCommonCmd(self, transport):
        """Standard command protocol handler"""
        serviceId = transport.serviceId
        resultCode = transport.resultCode
        packetSerialNum = transport.packetSerialNum
        packetTotalNum = transport.packetTotalNum

        print("     header: ", transport)
        if resultCode != 0:
            print("     !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            print("     --> failed result message")
            return


        dataPackage = transport.dataPackage()
        if dataPackage is None and service_id_class_mapping.get(serviceId, None) is not None:
            sid_class = service_id_class_mapping.get(serviceId, None)
            self.failed_msgs.setdefault(sid_class, [0])
            self.failed_msgs[sid_class][0] += 1
            print("     !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

        if not transport.notify:
            # Flag in transport.status decides whether this is a plain notification
            # (no CRC path) or a response/ack (CRC path).
            crcOk = transport.verifyCrc()
            print("     --> Got non notify packet: ", type(dataPackage), " crcok=", crcOk)
            print("      data: ", dataPackage)
            return

        print("    ---> Got result: ", type(dataPackage))
        print("      data: ", dataPackage)
        crcOk = transport.verifyCrc()
        if not crcOk:
            print("     !!!!!!!!!!!!!!!!!!!!!!! CRC check failed")


    def handleFileService(self, transport):
        """File service handler"""

        # @TODO: clean this up / break out sections - its hacked for one log right now
        print("    GOT FILE SERVICE: ", transport)
        if transport.serviceId == ServiceID.UX_EVEN_FILE_SERVICE_RAW_SEND_DATA_ID: # c5
            # data send channel
            if transport.destinationId == 2:
                print("     fileservice: GotSentFileData: ", transport.payload)
                print("     Got full file data: ", transport.payload)
                print("     Got full data crc: ", calc_crc_32(transport.payload))

            elif transport.destinationId == 1:
                print("     fileservice: SentFileData ack - result=", transport.payload[1])

        elif transport.serviceId == ServiceID.UX_EVEN_FILE_SERVICE_CMD_EXPORT_ID: # c6
            raise ValueError("not implemented")

        elif transport.serviceId == ServiceID.UX_EVEN_FILE_SERVICE_CMD_SEND_ID:  # c4
            # command send channel
            serviceCID = transport.payload[0]
            if serviceCID == EVEN_FILE_SERVICE_CMD_SEND_START:

                if transport.destinationId == 2:
                    print("     fileservice: CmdSendStart")
                    v1, v2, crc = struct.unpack_from("<III", transport.payload[1:], 0)
                    start_off = 1+4*3

                    payload_str = str(transport.payload[start_off:].decode('utf-8'))
                    print(f"      CmdSendStart header: field0={v1} field1={v2} dataCrc32={crc} notifyWhitelist={payload_str}")

                elif transport.destinationId == 1:
                    print("     fileservice: CmdSendStart ack - result=", transport.payload[1])


            elif serviceCID == EVEN_FILE_SERVICE_CMD_SEND_DATA:
                print("     fileservice: CmdSendData")



            elif serviceCID == EVEN_FILE_SERVICE_CMD_SEND_RESULT_CHECK:
                if transport.destinationId == 2:
                    print("     fileservice: CmdSendResultCheck")
                elif transport.destinationId == 1:
                    print("     fileservice: CmdSendResultCheck ack - result=", transport.payload[1])

            else:
                raise ValueError("not implemented")
        elif transport.serviceId == ServiceID.UX_EVEN_FILE_SERVICE_RAW_EXPORT_DATA_ID: # c7
            raise ValueError("not implemented")



    def accum_multipart_done(self, transport):
        """Check if this is a multi part packet and handle it accordingly

            If there is a previous packet in the chain (based on (serviceId, syncId)) -
                accumulate the payload with the previous accumulated payload.

            If we're in a multi part packet, then save off the accumulated payload for
            use when the next message comes

            Once the last message in a message chain is seen, actually return the
            last transport packet with a full accumulated payload for the entire message chain
        """
        serviceId = transport.serviceId
        packetSerialNum = transport.packetSerialNum
        packetTotalNum = transport.packetTotalNum

        msg_key = (serviceId, transport.syncId)

        failed = False

        if transport.packetSerialNum > 1:
            assert msg_key in self.partials
            prev, failed = self.partials[msg_key]

            if transport.packetSerialNum != prev.packetSerialNum + 1:
                print("        !!!! Dropped/missing packet in sequence - expect parsing to fail")
                failed = True


            transport.payload = prev.payload + transport.payload


        if packetSerialNum < packetTotalNum:
            print("     Multi part packet not complete - waiting for more: transport=", transport)
            self.partials[msg_key] = (transport, failed)
            return None


        if msg_key in self.partials:
            del self.partials[msg_key]

        assert packetSerialNum == packetTotalNum

        return transport



    # main packet handler
    def handle(self, packet):
        """Handle a single new packet

            It's expected that you only call this with packets which are:
            * btatt protocol read / write
            * pre-filtered for the payload starting with the 0xAA starting byte
        """

        # parse transport header
        transport = EvenBleTransport.fromBytes(packet)
        assert transport

        # check and accumulate data if this is a multipart send
        # if this is multipart and the message isn't finished then None will be returned
        transport = self.accum_multipart_done(transport)

        # if we're in the middle of a multipart message, then don't process
        if transport is None:
            return


        # route to different handlers depending on which serviceID it is
        #   In the actual glasses it looks like there are:
        #       * file service with its own protocol/objects
        #       * ota service with its own protocol/objects
        #       * stream handling with its own protocol
        #       * common command handling which uses proto buffers
        #
        #   Currently this only implements a part of the file service and the command service
        if transport.serviceId in [
            ServiceID.UX_EVEN_FILE_SERVICE_RAW_SEND_DATA_ID,
            ServiceID.UX_EVEN_FILE_SERVICE_CMD_EXPORT_ID,
            ServiceID.UX_EVEN_FILE_SERVICE_CMD_SEND_ID,
            ServiceID.UX_EVEN_FILE_SERVICE_RAW_EXPORT_DATA_ID,
        ]:
            self.handleFileService(transport)

        else:
            self.handleCommonCmd(transport)





def parse_text_log(filename):
    """Parse original text logs (posted by soxi) for messages

        These seemed to be missing a lot of packets, but it's left here in case its useful.

        Find any 0xAA payload to process
    """
    handler = MsgHandler()
    for line in open(filename):
        line = line.strip()
        search_str = 'Notification received from'
        print(line)
        if search_str in line:
            sub_search_str = ', value: (0x) '
            index = line.index(sub_search_str) + len(sub_search_str)
            res_data = line[index:]

            print("    got_cmd: ", res_data)

            sub_bytes = res_data.split('-')
            print("     Header(hex): ", sub_bytes[:8])

            data_bytes = []
            for x in sub_bytes:
                data_bytes.append(int(x, base=16))

            print("     Header(int): ", data_bytes[:8])


            # convert to binary
            data_bytes = bytes(data_bytes)
            print("     -> ", data_bytes)


            handler.handle(data_bytes)


def tshark_maybe_process_snoop_log_to_csv(filename):
    # run tshark to get the right columns if this isn't already in csv format for us
    if not filename.endswith(".csv"):
        print("Assuming this is a raw snoop log, generating csv first")
        os.system(f"tshark -r {filename} -2  -Y btatt  -T fields -e bluetooth.src -e _ws.col.Source -e bluetooth.dst -e _ws.col.Destination -e btatt.length -e btatt.value -E separator=, > _temp_snooplog.csv")
        filename = '_temp_snooplog.csv'

    return filename


# parse and print packets from a btsnoop log
def parse_snoop_log_csv(filename):
    """Parse original text logs (posted by soxi) for messages

        These seemed to be missing a lot of packets, but it's left here in case its useful.

        Find any 0xAA payload to process
    """

    # maybe process if this isn't already a csv
    filename = tshark_maybe_process_snoop_log_to_csv(filename)


    # main message handler
    handler = MsgHandler()

    # read the tshark csv
    df = pd.read_csv(filename)
    df.columns = [
        'srcmac',
        'srcstr',
        'dstmac',
        'dststr',
        'len',
        'data'
    ]


    df['data'] = df['data'].fillna('').astype(str)
    for i in range(len(df)):
        r = df.iloc[i,:]

        # filter for if this is a message between glasses, phone, and or ring
        src_is_glasses = ('Even G2' in r['srcstr'])
        dst_is_glasses = ('Even G2' in r['dststr'])

        src_is_ring = ('Even R1' in r['srcstr'])
        dst_is_ring = ('Even R1' in r['dststr'])

        src = r['srcstr']
        dest = r['dststr']

        if src_is_glasses or dst_is_glasses or src_is_ring or dst_is_ring:
            data = r['data']
            if data:
                print("------------------------------------------------------")
                print("Msg: ", data)
                print(f"    {src} -> {dest}")

                if data.startswith('aa'):
                    # convert the data to bytes (its in a hex string in the output)
                    assert len(data) % 2 == 0
                    vals = []
                    for i in range(0, len(data), 2):
                        vals.append(int(data[i:(i+2)], base=16))

                    data_bytes = bytes(vals)

                    # actually handle the message
                    handler.handle(data_bytes)

    return handler





if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage:  python parser.py snoop_log_filename")
        sys.exit(1)

    handler = parse_snoop_log_csv(sys.argv[1])

    # this is hacky but just for debugging, I dump out a failed msg count for each
    # msg type that failed
    if handler.failed_msgs:
        print("---------------------------------------------------------------------------------")
        print("Failed message: ")
        for k, v in handler.failed_msgs.items():
            print(   "type=", k, " : nfailed=", v[0])
