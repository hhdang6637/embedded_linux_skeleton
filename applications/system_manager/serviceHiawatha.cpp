/*
 * service_hiawatha.cpp
 *
 *  Created on: Jul 22, 2018
 *      Author: hhdang
 */
#include <sys/stat.h>
#include <sys/types.h>

#include <fstream>
#include "serviceHiawatha.h"


#define HIAWATHA_CONFIG_DIR "/tmp/configs/hiawahta/"

namespace app
{

serviceHiawatha::serviceHiawatha()
{
    // TODO Auto-generated constructor stub
}

serviceHiawatha::~serviceHiawatha()
{
    // TODO Auto-generated destructor stub
}

std::string serviceHiawatha::service_name()
{
    static std::string service_name("hiawatha");
    return service_name;
}

serviceHiawatha *serviceHiawatha::s_instance = 0;

serviceHiawatha* serviceHiawatha::getInstance()
{
    if (s_instance == 0) {
        s_instance = new serviceHiawatha();
    }

    return s_instance;
}

bool serviceHiawatha::init()
{
    mkdir(HIAWATHA_CONFIG_DIR, 0755);

    std::ofstream hiawatha_conf_file(HIAWATHA_CONFIG_DIR"hiawatha.conf");

    if (hiawatha_conf_file.is_open()) {
        hiawatha_conf_file <<
                "set LOG_DIR        = /var/log/hiawatha\n"
                "set WEBROOT_DIR    = /var/www/hiawatha/public\n"
                "set WOKRING_DIR    = /tmp/hiawatha\n"
                "ConnectionsTotal   = 1000\n"
                "ConnectionsPerIP   = 25\n"
                "SystemLogfile      = LOG_DIR/system.log\n"
                "GarbageLogfile     = LOG_DIR/garbage.log\n"
                "ExploitLogfile     = LOG_DIR/exploit.log\n"
                "AccessLogfile      = LOG_DIR/access.log\n"
                "ErrorLogfile       = LOG_DIR/error.log\n"
                "Binding {\n"
                "    Port = 80\n"
                "}\n"
                "Hostname       = 127.0.0.1\n"
                "WebsiteRoot    = WEBROOT_DIR\n"
                "StartFile      = index.html\n"
                "PIDfile        = WOKRING_DIR/hiawatha.pid\n"
                "WorkDirectory  = WOKRING_DIR\n"
                "ShowIndex      = WEBROOT_DIR/index.html\n"
                "#UseFastCGI    = WebHandlerFCGI\n"
                "UseToolkit     = WebHandlerToolkit\n"
                "\n"
                "FastCGIserver {\n"
                "        FastCGIid = WebHandlerFCGI\n"
                "        ConnectTo = /tmp/web_handler.socket\n"
                "        SessionTimeout = 30\n"
                "}\n"
                "\n"
                "UrlToolkit {\n"
                "    ToolkitID = WebHandlerToolkit\n"
                "    RequestURI isfile Return\n"
                "    Match ^/(.*) Rewrite / Continue\n"
                "    Match / UseFastCGI WebHandlerFCGI\n"
                "}\n"
                "\n";

        hiawatha_conf_file.close();
    }

    std::ofstream hiawatha_mimetype_conf_file(HIAWATHA_CONFIG_DIR"mimetype.conf");

    if (hiawatha_mimetype_conf_file.is_open()) {
        hiawatha_mimetype_conf_file
                << "# Application\n"
                        "#\n"
                        "application/java-archive        jar\n"
                        "application/json            json\n"
                        "application/pdf             pdf\n"
                        "application/pkcs-crl            crl\n"
                        "application/postscript          ps ai eps\n"
                        "application/vnd.google-earth.kml+xml    kml\n"
                        "application/vnd.google-earth.kmz    kmz\n"
                        "application/xml             xml xsl xslt\n"
                        "application/x-binary            bin\n"
                        "application/x-bzip2         bz2\n"
                        "application/x-debian-package        deb\n"
                        "application/x-dvi           dvi\n"
                        "application/x-gzip          gz\n"
                        "application/\n"
                        "x-java-vm           class\n"
                        "application/x-latex         latex\n"
                        "application/x-msdos-program     com exe bat dll\n"
                        "application/x-redhat-packet-manager rpm\n"
                        "application/x-shockwave-flash       swf swfl\n"
                        "application/x-sh            sh\n"
                        "application/x-tar           tgz tar\n"
                        "application/x-trash         bak old\n"
                        "application/x-x509-ca-cert      crt cer pem\n"
                        "application/zip             zip\n"
                        "\n"
                        "# Application / Office\n"
                        "#\n"
                        "application/excel           xls xlb xlc xlt\n"
                        "application/msaccess            mdb\n"
                        "application/msword          doc dot\n"
                        "application/powerpoint          ppt pps pot\n"
                        "application/vnd.openxmlformats-officedocument.presentationml.presentation   pptx\n"
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet       xlsx\n"
                        "application/vnd.openxmlformats-officedocument.wordprocessingml.document     docx\n"
                        "application/vnd.oasis.opendocument.graphics                 odg\n"
                        "application/vnd.oasis.opendocument.presentation                 odp\n"
                        "application/vnd.oasis.opendocument.spreadsheet                  ods\n"
                        "application/vnd.oasis.opendocument.text                     odt\n"
                        "\n"
                        "# Audio\n"
                        "#\n"
                        "audio/basic             au snd\n"
                        "audio/midi              mid midi rmi\n"
                        "audio/mp4a-latm             m4a m4b m4p\n"
                        "audio/mpeg              mp3 m4a\n"
                        "audio/ogg               ogg\n"
                        "audio/x-aac             aac\n"
                        "audio/x-wav             wav\n"
                        "\n"
                        "# Image\n"
                        "#\n"
                        "image/bmp               bmp\n"
                        "image/gif               gif\n"
                        "image/jpeg              jpg jpeg jpe\n"
                        "image/pcx               pcx\n"
                        "image/png               png\n"
                        "image/svg+xml               svg svgz\n"
                        "image/tiff              tiff tif\n"
                        "image/vnd.nok-oplogo-color      nol\n"
                        "image/x-icon                ico\n"
                        "\n"
                        "# Text\n"
                        "#\n"
                        "text/cache-manifest         cache\n"
                        "text/calendar               ics\n"
                        "text/css                css\n"
                        "text/csv                csv\n"
                        "text/html               htm html xhtml\n"
                        "text/javascript             js\n"
                        "text/markdown               md\n"
                        "text/plain              asc asm txt text diff java log\n"
                        "text/richtext               rtf\n"
                        "text/vnd.wap.wml            wml\n"
                        "text/x-c                c h\n"
                        "text/x-c++src               c++ cpp cxx cc\n"
                        "text/x-pascal               p pas\n"
                        "text/x-tcl              tcl tk\n"
                        "text/x-tex              tex ltx sty cls\n"
                        "\n"
                        "# Video\n"
                        "#\n"
                        "video/3gpp              3gp 3gpp amr\n"
                        "video/avi               avi\n"
                        "video/x-matroska            mkv\n"
                        "video/mpeg              mpeg mpg mpe mp2\n"
                        "video/mp4               mp4\n"
                        "video/quicktime             qt mov\n"
                        "video/flv                               flv\n"
                        "video/x-ms-asf              asf asr asx\n"
                        "\n"
                        "# Virtual reality\n"
                        "#\n"
                        "x-world/x-vrml              flr vrm vrml wrl wrz xaf xof\n"
                        "\n";

        hiawatha_mimetype_conf_file.close();
    }

    return true;
}

bool serviceHiawatha::start()
{
    std::string command;
    command = "hiawatha -c ";
    command += HIAWATHA_CONFIG_DIR;

    system(command.c_str());

    return true;
}

} /* namespace app */
