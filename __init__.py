# Copyright 2018 Nagravision SA
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

import importlib
import json
import struct
import sys

from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView, BinaryViewType
from binaryninja.enums import (
    BranchType, FlagRole, InstructionTextTokenType, LowLevelILFlagCondition,
    LowLevelILOperation, SegmentFlag, SymbolType
)
from binaryninja.interaction import get_choice_input, get_open_filename_input
from binaryninja.log import log_error
from binaryninja.settings import Settings
from binaryninja.types import Symbol, Type

PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3


class CortexView(BinaryView):
    name = "CortexFirmware"
    long_name = "ARM Cortex Firmware file"

    @classmethod
    def get_load_settings_for_data(cls, data):
        registered_view = cls.registered_view_type
        assert registered_view is not None
        view = registered_view.parse(data)
        assert view is not None

        load_settings = registered_view.get_default_load_settings_for_data(view)

        arch = Architecture['thumb2']
        load_settings.update_property(
            "loader.architecture", json.dumps({'default': arch.name})
        )
        load_settings.update_property(
            "loader.platform",
            json.dumps({'default': arch.standalone_platform.name})
        )

        MCUS = [
            "STM32F0",
            "STM32F1",
            "STM32F2",
            "STM32F3",
            "STM32F4",
            "STM32F7",
            "STM32L0",
            "STM32L1",
            "STM32L4",
            "EFM32TG",
            "EFM32G",
            "EFM32LG",
            "EFM32GG",
            "EFM32HG",
            "EFM32WG",
            "EZR32WG",
            "LPC13XX",
            "LPC17XX",
            "LPC43XX_M4",
            "LPC43XX_M0",
            "SAM3A",
            "SAM3N",
            "SAM3S",
            "SAM3U",
            "SAM3X",
            "SAM4L",
            "SAMD",
            "LM3S",
            "LM4F",
            "MSP432E4",
            "VF6XX",
        ]

        load_settings.register_setting(
            "loader.cortex_m.mcu",
            json.dumps(
                {
                    "title": "MCU Family",
                    "type": "string",
                    "enum": MCUS,
                    "default": MCUS[0],
                    "description": "Which family of microcontrollers to use"
                }
            )
        )

        return load_settings

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.arch = Architecture['thumb2']
        self.platform = Architecture['thumb2'].standalone_platform
        self._entry_point = 0

    def init(self):
        # We won't know the MCU the user selected until the binary view is finalized
        BinaryViewType[self.name].add_binaryview_finalized_event(
            self.bv_finalized_callback
        )

        self.add_analysis_completion_event(self.analysis_complete_callback)

        return True

    def bv_finalized_callback(self, _bv):
        self.navigate(f'Linear:{self.name}', 0)
        chosen_mcu = self.get_load_settings(self.name
                                           ).get_string('loader.cortex_m.mcu', self)
        assert chosen_mcu is not None

        mcu_lib = importlib.import_module(
            "binaryninja_cortex.platforms." + chosen_mcu
        )
        mcu = mcu_lib.Chip

        # Add RAM segment
        self.add_auto_segment(
            mcu.RAM_OFF, 0xffff, 0, 0, SegmentFlag.SegmentReadable
            | SegmentFlag.SegmentWritable | SegmentFlag.SegmentExecutable
        )

        # Add peripherals segment
        self.add_auto_segment(
            mcu.PERIPH_OFF, 0x10000000, 0, 0,
            SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable
        )

        # Add flash segment, assume flash < 2MB
        self.add_auto_segment(
            mcu.ROM_OFF, 0x200000, 0, 0x200000,
            SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable
        )

        # Add IVT symbols

        # Create SP_VALUE data pointer
        self.define_auto_symbol_and_var_or_function(
            Symbol(SymbolType.DataSymbol, mcu.ROM_OFF, mcu.IRQ[0]),
            Type.pointer(self.arch, Type.void(), const=True), self.platform
        )

        reader = self.reader(mcu.ROM_OFF)

        addr = reader.read32()
        self.define_auto_symbol(
            Symbol(SymbolType.DataSymbol, addr, "p_{}".format(mcu.IRQ[0]))
        )

        # All other vectors are function pointers
        for i in range(1, len(mcu.IRQ)):
            # Add vector symbol
            self.define_auto_symbol_and_var_or_function(
                Symbol(
                    SymbolType.DataSymbol, mcu.ROM_OFF + (4 * i), mcu.IRQ[i]
                ), Type.pointer(self.arch, Type.void(), const=True),
                self.platform
            )

            # Add vector handler function
            addr = reader.read32() & ~1
            if addr != 0:
                self.define_auto_symbol(
                    Symbol(
                        SymbolType.FunctionSymbol, addr,
                        "f_{}".format(mcu.IRQ[i])
                    )
                )

                self.add_function(addr, self.platform)

        self._entry_point = self.symbols['f_RESET_IRQ'][0].address
        self.add_entry_point(self._entry_point, self.platform)

        return True

    def analysis_complete_callback(self):
        # self.navigate(
        #     f'Linear:{self.name}', self.symbols['f_RESET_IRQ'][0].address
        # )
        pass

    @classmethod
    def is_valid_for_data(self, data):
        # Read two DWORDS
        ivt = data.read(0, 8)
        if PY2:
            if ord(ivt[3]) > 0x20:
                # SP value should be in SRAM (max 0x20......)
                return False
            if ord(ivt[7]) > 0x08:
                # Reset vector should be in flash (max 0x08......)
                return False
        else:
            if ivt[3] > 0x20:
                # SP value should be in SRAM (max 0x20......)
                return False
            if ivt[7] > 0x08:
                # Reset vector should be in flash (max 0x08......)
                return False
        return True

    def perform_get_address_size(self):
        return self.arch.address_size

    def perform_get_entry_point(self):
        # Note that this may be zero if this function is called before the binary view
        # is finalized
        return self._entry_point


CortexView.register()
