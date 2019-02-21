#
# This file is the DynamoRIO recipe.
#

SUMMARY = "DynamoRIO dynamic instrumentation"
SECTION = "PETALINUX/apps"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

SRC_URI = "file://${BP}.tar.gz \
        "
inherit bin_package

INSANE_SKIP_${PN} += "staticdev"
INSANE_SKIP_${PN} += "dev-so"


