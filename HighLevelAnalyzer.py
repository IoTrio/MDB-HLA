# MDB-HLA - Multi-Drop-Bus High-Level Analyzer
# Copyright 2022, IoTrio GmbH, Amir El Sewisy
# SPDX-License-Identifier: Apache-2.0

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, ChoicesSetting


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    vmc_peri_choices = {'VMC->PERI': False, 'PERI->VMC': True}
    vmc_peri_setting = ChoicesSetting(label='VMC->PERI', choices=vmc_peri_choices.keys())

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'mytype': {
            'format': 'Output type: {{type}}, Input type: {{data.input_type}}'
        }
    }

    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.data = bytes()
        self.mode_bits = []

    def process_cmd_vmc_peri(self):
        # check if it's a response
        if not self.mode_bits[0] and len(self.data) == 1:
            if int(self.data[0]) == 0x00:
                return AnalyzerFrame('VMC->PERI', self.start_time, self.end_time, {
                                    'cmd': 'ACK',
                                })
            elif int(self.data[0]) == 0xAA:
                return AnalyzerFrame('VMC->PERI', self.start_time, self.end_time, {
                                    'cmd': 'RET',
                                })
            elif int(self.data[0]) == 0xFF:
                return AnalyzerFrame('VMC->PERI', self.start_time, self.end_time, {
                                    'cmd': 'NAK',
                                })
        # check validity of command
        valid = True
        if self.mode_bits[0] != True:
            valid = False
        for bit in self.mode_bits[1:]:
            if bit == True:
                valid = False
        if not valid:
            return AnalyzerFrame('VMC->PERI', self.start_time, self.end_time, {
                        'error': 'Invalid Mode bit'
                    })
        chk = 0
        for b in self.data[:-1]:
            chk = (chk + int(b)) % 256
        if int(self.data[-1]) != chk:
            return AnalyzerFrame('VMC->PERI', self.start_time, self.end_time, {
                        'error': 'Invalid CHK, expected {}, got {}.'.format(chk, int(self.data[-1]))
                    })
        # parse command
        addr = int(self.data[0])
        vmc_data = self.data[1:-1]
        if addr == 0x08:
            return AnalyzerFrame('VMC->CC', self.start_time, self.end_time, {
                            'cmd': 'RESET'
                        })
        elif addr == 0x09:
            return AnalyzerFrame('VMC->CC', self.start_time, self.end_time, {
                            'cmd': 'SETUP'
                        })
        elif addr == 0x0A:
            return AnalyzerFrame('VMC->CC', self.start_time, self.end_time, {
                            'cmd': 'TUBE STATUS'
                        })
        elif addr == 0x0B:
            return AnalyzerFrame('VMC->CC', self.start_time, self.end_time, {
                            'cmd': 'POLL'
                        })
        elif addr == 0x0C:
            if len(vmc_data) != 4:
                return AnalyzerFrame('VMC->CC', self.start_time, self.end_time, {
                                'cmd': 'COIN TYPE',
                                'error': 'invalid VMC data length for COIN TYPE',
                                'vmc_data': vmc_data,
                            })
            return AnalyzerFrame('VMC->CC', self.start_time, self.end_time, {
                            'cmd': 'COIN TYPE',
                            'vmc_data': vmc_data,
                            'mdb_text': 'coin enable: {:04X}; manual dispense enable: {:04X}'.format(int.from_bytes(vmc_data[0:2], 'big'), int.from_bytes(vmc_data[2:4], 'big'))
                        })
        elif addr == 0x0D:
            if len(vmc_data) != 1:
                return AnalyzerFrame('VMC->CC', self.start_time, self.end_time, {
                                'cmd': 'DISPENSE',
                                'error': 'invalid VMC data length for DISPENSE',
                                'vmc_data': vmc_data,
                            })
            coin_values = [0.01, 0.02, 0.05, 0.10, 0.20, 0.50, 1.00, 2.00, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
            d_coin_count = int((vmc_data[0] & 0xF0) >> 4)
            d_coin_type = int(vmc_data[0] & 0x0F)
            dispense = "{} x cointype {}".format(d_coin_count, d_coin_type)
            if d_coin_type < len(coin_values):
                dispense = "{} x EUR {:.2f} = EUR {:.2f}".format(d_coin_count, coin_values[d_coin_type], coin_values[d_coin_type] * d_coin_count)
            return AnalyzerFrame('VMC->CC', self.start_time, self.end_time, {
                            'cmd': 'DISPENSE',
                            'vmc_data': vmc_data,
                            'mdb_text': dispense
                        })
        elif addr == 0x0F:
            if len(vmc_data) < 1:
                return AnalyzerFrame('VMC->CC', self.start_time, self.end_time, {
                                'cmd': 'EXPANSION',
                                'error': 'Invalid expansion command: subcommand missing'
                            })
            subcommand = int(vmc_data[0])
            if subcommand == 0x00:
                return AnalyzerFrame('VMC->CC', self.start_time, self.end_time, {
                                'cmd': 'EXPANSION: IDENTIFICATION'
                            })
            elif subcommand == 0x01:
                return AnalyzerFrame('VMC->CC', self.start_time, self.end_time, {
                                'cmd': 'EXPANSION: FEATURE ENABLE'
                            })
            elif subcommand == 0x02:
                if len(vmc_data) == 2:
                    return AnalyzerFrame('VMC->CC', self.start_time, self.end_time, {
                                    'cmd': 'EXPANSION: PAYOUT',
                                    'vmc_data': vmc_data[1:],
                                    'mdb_text': 'Value: {}'.format(int(vmc_data[1]))
                                })
                else:
                    return AnalyzerFrame('VMC->CC', self.start_time, self.end_time, {
                                    'cmd': 'EXPANSION: PAYOUT',
                                    'vmc_data': vmc_data[1:],
                                    'error': 'Invalid VMC data length'
                                })
            elif subcommand == 0x03:
                return AnalyzerFrame('VMC->CC', self.start_time, self.end_time, {
                                'cmd': 'EXPANSION: PAYOUT STATUS',
                            })
            elif subcommand == 0x04:
                return AnalyzerFrame('VMC->CC', self.start_time, self.end_time, {
                                'cmd': 'EXPANSION: PAYOUT VALUE POOL',
                            })
            elif subcommand == 0x05:
                return AnalyzerFrame('VMC->CC', self.start_time, self.end_time, {
                                'cmd': 'EXPANSION: SEND DIAGNOSTIC STATUS',
                            })
            elif subcommand == 0x06:
                return AnalyzerFrame('VMC->CC', self.start_time, self.end_time, {
                                'cmd': 'EXPANSION: SEND CONTROLLED MANUAL FILL REPORT',
                            })
            elif subcommand == 0x07:
                return AnalyzerFrame('VMC->CC', self.start_time, self.end_time, {
                                'cmd': 'EXPANSION: SEND CONTROLLED MANUAL PAYOUT REPORT',
                            })
            elif subcommand in range(0xFA, 0xFF):
                return AnalyzerFrame('VMC->CC', self.start_time, self.end_time, {
                                'cmd': 'EXPANSION: FTL',
                            })
            elif subcommand == 0xFF:
                return AnalyzerFrame('VMC->CC', self.start_time, self.end_time, {
                                'cmd': 'EXPANSION: DIAGNOSTICS',
                            })
            else:
                return AnalyzerFrame('VMC->CC', self.start_time, self.end_time, {
                                'cmd': 'EXPANSION: UNKNOWN',
                            })
        elif addr == 0x10:
            return AnalyzerFrame('VMC->CD1', self.start_time, self.end_time, {
                                'cmd': 'RESET',
                            })
        elif addr == 0x60:
            return AnalyzerFrame('VMC->CD2', self.start_time, self.end_time, {
                                'cmd': 'RESET',
                            })
        elif addr == 0x30:
            return AnalyzerFrame('VMC->BV', self.start_time, self.end_time, {
                                'cmd': 'RESET',
                            })
        elif addr == 0x31:
            return AnalyzerFrame('VMC->BV', self.start_time, self.end_time, {
                                'cmd': 'SETUP',
                            })
        elif addr == 0x32:
            return AnalyzerFrame('VMC->BV', self.start_time, self.end_time, {
                                'cmd': 'SECURITY',
                                'vmc_data': vmc_data
                            })
        elif addr == 0x33:
            return AnalyzerFrame('VMC->BV', self.start_time, self.end_time, {
                                'cmd': 'POLL',
                            })
        elif addr == 0x34:
            return AnalyzerFrame('VMC->BV', self.start_time, self.end_time, {
                                'cmd': 'BILL TYPE',
                                'vmc_data': vmc_data
                            })
        elif addr == 0x35:
            return AnalyzerFrame('VMC->BV', self.start_time, self.end_time, {
                                'cmd': 'ESCROW',
                                'vmc_data': vmc_data
                            })
        elif addr == 0x36:
            return AnalyzerFrame('VMC->BV', self.start_time, self.end_time, {
                                'cmd': 'STACKER',
                            })
        elif addr == 0x37:
            return AnalyzerFrame('VMC->BV', self.start_time, self.end_time, {
                                'cmd': 'EXPANSION',
                                'vmc_data': vmc_data
                            })
        else:
            return AnalyzerFrame('VMC->PERI', self.start_time, self.end_time, {
                            'cmd': '0x{:02X}'.format(addr),
                            'vmc_data': vmc_data
                        })
        
    def process_vmc_peri(self, ctrl_bit, data_byte, start_time, end_time, timeout):
        ret = None
        # check timeout
        if timeout or ctrl_bit:
            if len(self.data) != 0:
                ret = self.process_cmd_vmc_peri()
            self.data = bytes()
            self.mode_bits = []
        self.data += data_byte
        self.mode_bits += [ctrl_bit]
        self.end_time = end_time
        if len(self.data) == 1:
            self.start_time = start_time
        return ret

    def process_frame_peri_vmc(self):
        # check if it's a response to VMC data
        if len(self.data) == 1:
            if int(self.data[0]) == 0x00:
                return AnalyzerFrame('PERI->VMC', self.start_time, self.end_time, {
                                    'resp': 'ACK'
                                })
            elif int(self.data[0]) == 0xFF:
                return AnalyzerFrame('PERI->VMC', self.start_time, self.end_time, {
                                    'resp': 'NAK'
                                })
        # check validity of chk
        chk = 0
        for b in self.data[:-1]:
            chk = (chk + int(b)) % 256
        if int(self.data[-1]) != chk:
            return AnalyzerFrame('PERI->VMC', self.start_time, self.end_time, {
                        'error': 'Invalid CHK, expected {}, got {}.'.format(chk, int(self.data[-1]))
                    })
        # TODO properly parsing response requires knowing command
        peri_data = self.data[:-1]
        coin_values = [0.01, 0.02, 0.05, 0.10, 0.20, 0.50, 1.00, 2.00, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
        if len(peri_data) == 23:
            return AnalyzerFrame('PERI->VMC', self.start_time, self.end_time, {
                            'resp': 'DATA',
                            'peri_data': self.data[:-1],
                            'mdb_cc_text': 'Feature level: {}; Country code: {:04X}; Coin Scaling Factor: {}; \
                                Decimal places: {}; Coin type routing: {:04X}; Coin type credit: {}'.format(
                                    int(peri_data[0]), int.from_bytes(peri_data[1:3], 'big'), int(peri_data[3]), int(peri_data[4]),
                                    int.from_bytes(peri_data[5:7], 'big'), [int(b) for b in peri_data[7:23]]
                                    )
                        })
        elif len(peri_data) == 18:
            return AnalyzerFrame('PERI->VMC', self.start_time, self.end_time, {
                            'resp': 'DATA',
                            'peri_data': self.data[:-1],
                            'mdb_cc_text': 'Tube full status: {:04X}; Tube status: {};'.format(
                                    int.from_bytes(peri_data[0:2], 'big'), [int(b) for b in peri_data[2:18]]
                                    )
                        })
        elif len(peri_data) <= 16:
            mdb_cc_text = ''
            idx = 0
            while idx < len(peri_data):
                if int(peri_data[idx]) >= 128:
                    if idx + 1 >= len(peri_data):
                        mdb_cc_text += ' BYTE NOT PARSED;'
                        idx += 1
                        continue
                    n_coins = int((peri_data[idx] & 0b01110000) >> 4)
                    coin_type = int(peri_data[idx] & 0b00001111)
                    mdb_cc_text += ' Coins dispensed manually: {} x cointype {} (EUR {:.2f}) = EUR {:.2f}, {} in tube;'.format(
                        n_coins, coin_type, coin_values[coin_type], coin_values[coin_type] * n_coins, int(peri_data[idx + 1])
                    )
                    idx += 2
                elif int(peri_data[idx]) > 64:
                    if idx + 1 >= len(peri_data):
                        mdb_cc_text += ' BYTE NOT PARSED;'
                        idx += 1
                        continue
                    routing = int((peri_data[idx] & 0b00110000) >> 4)
                    routing_str = None
                    if routing == 0:
                        routing_str = 'CASH BOX'
                    elif routing == 1:
                        routing_str = 'TUBES'
                    elif routing == 2:
                        routing_str = 'NOT USED'
                    else:
                        routing_str = 'REJECT'
                    coin_type = int(peri_data[idx] & 0b00001111)
                    mdb_cc_text += ' Coins deposited: routing {}, cointype {} (EUR {:.2f}), {} in tube;'.format(
                        routing_str, coin_type, coin_values[coin_type], int(peri_data[idx + 1])
                    )
                    idx += 2
                elif int(peri_data[idx]) > 32:
                    mdb_cc_text += ' Slugs: {};'.format(int(peri_data[idx] & 0x0F))
                    idx += 1
                else:
                    status = 'UNKNOWN'
                    if int(peri_data[idx]) == 0b00000001:
                        status = 'ESCROW REQUEST'
                    elif int(peri_data[idx]) == 0b00000010:
                        status = 'CHANGER PAYOUT BUSY'
                    elif int(peri_data[idx]) == 0b00000011:
                        status = 'NO CREDIT'
                    elif int(peri_data[idx]) == 0b00000100:
                        status = 'DEFECTIVE TUBE SENSOR'
                    elif int(peri_data[idx]) == 0b00000101:
                        status = 'DOUBLE ARRIVAL'
                    elif int(peri_data[idx]) == 0b00000110:
                        status = 'ACCEPTOR UNPLUGGED'
                    elif int(peri_data[idx]) == 0b00000111:
                        status = 'TUBE JAM'
                    elif int(peri_data[idx]) == 0b00001000:
                        status = 'ROM CHECKSUM ERROR'
                    elif int(peri_data[idx]) == 0b00001001:
                        status = 'COIN ROUTING ERROR'
                    elif int(peri_data[idx]) == 0b00001010:
                        status = 'CHANGER BUSY'
                    elif int(peri_data[idx]) == 0b00001011:
                        status = 'CHANGER RESET'
                    elif int(peri_data[idx]) == 0b00001100:
                        status = 'COIN JAM'
                    elif int(peri_data[idx]) == 0b00001101:
                        status = 'POSSIBLE THEFT'
                    mdb_cc_text += ' Status: {};'.format(status)
                    idx += 1
            return AnalyzerFrame('PERI->VMC', self.start_time, self.end_time, {
                            'resp': 'DATA',
                            'peri_data': peri_data,
                            'mdb_cc_text': mdb_cc_text
                        })
        return AnalyzerFrame('PERI->VMC', self.start_time, self.end_time, {
                            'resp': 'DATA',
                            'peri_data': peri_data
                        })
    def process_peri_vmc(self, ctrl_bit, data_byte, start_time, end_time, timeout):
        self.data += data_byte
        if self.start_time is None:
            self.start_time = start_time
        self.end_time = end_time
        ret = None
        if ctrl_bit:
            ret = self.process_frame_peri_vmc()
            self.start_time = None
            self.data = bytes()
        return ret
        
    def decode(self, frame: AnalyzerFrame):
        data_byte = frame.data['data'][1:]
        ctrl_bit = frame.data['address']
        timeout = False
        if self.end_time is not None:
            delta_ms = float(frame.start_time - self.end_time) * 1000.0
            timeout = (delta_ms > 1.25)
        
        if self.vmc_peri_choices.get(str(self.vmc_peri_setting)):
            return self.process_peri_vmc(ctrl_bit, data_byte, frame.start_time, frame.end_time, timeout)
        else:
            return self.process_vmc_peri(ctrl_bit, data_byte, frame.start_time, frame.end_time, timeout)
