###########################################################################
# Copyright 2017 IoT.bzh
#
# author: Jose Bollo <jose.bollo@iot.bzh>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###########################################################################

PROJECT_TARGET_ADD(afb-uds-ble-id-init-binding)

add_library(afb-uds-ble-id-init-binding MODULE
	uds-ble-id-init-service.c
	aia-uds-bluez.c
)

set_target_properties(afb-uds-ble-id-init-binding PROPERTIES
        LABELS "BINDING"
	PREFIX ""
	COMPILE_FLAGS "${libsystemd_CFLAGS}"
	INCLUDE_DIRECTORIES "${libsystemd_INCLUDE_DIRS}"
        LINK_FLAGS "${BINDINGS_LINK_FLAG}"
	LINK_LIBRARIES "${libsystemd_LIBRARIES}"
        OUTPUT_NAME "${TARGET_NAME}"
)

