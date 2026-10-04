"""Пакет ОС → название продукта в БДУ.

Пакеты называются иначе, чем продукты в БДУ (openssh-server → OpenSSH, libssl3t64 → OpenSSL,
linux-image-6.8.0-142-generic → Linux). Сопоставление явное: точный список псевдонимов, а для
остальных — совпадение имени пакета с названием продукта целиком. Подстрочных совпадений нет:
«git» не должен находить «GitLab», а «less» — «Lessbits».
"""
import re

# Регулярное выражение по имени пакета → название продукта в БДУ (в нижнем регистре).
ALIASES: list[tuple[re.Pattern, str]] = [
    (re.compile(p), product)
    for p, product in [
        (r"^openssh-(server|client|sftp-server)$", "openssh"),
        (r"^(openssl|libssl3(t64)?|libssl1\.1)$", "openssl"),
        (r"^(curl|libcurl\d*(t64)?(-gnutls)?)$", "curl"),
        (r"^libc6$", "glibc"),
        (r"^(xz-utils|liblzma5)$", "xz utils"),
        (r"^(polkitd|policykit-1|libpolkit-gobject-1-0)$", "polkit"),
        (r"^(libpam0g|libpam-modules)$", "linux-pam"),
        (r"^libexpat1$", "expat"),
        (r"^libxml2$", "libxml2"),
        (r"^zlib1g$", "zlib"),
        (r"^libsqlite3-0$", "sqlite"),
        (r"^(gnupg|gpg)$", "gnupg"),
        (r"^python3\.\d+$", "python"),
        (r"^(vim|vim-tiny|vim-runtime)$", "vim"),
        (r"^(containerd|containerd\.io)$", "containerd"),
        (r"^runc$", "runc"),
        (r"^apache2$", "apache http server"),
        (r"^bind9$", "bind"),
        (r"^(postgresql-\d+)$", "postgresql"),
        (r"^(samba|samba-common-bin)$", "samba"),
        (r"^libpng16-16(t64)?$", "libpng"),
        (r"^libtiff6$", "libtiff"),
        (r"^(ghostscript|libgs10)$", "ghostscript"),
        (r"^(imagemagick|imagemagick-6\.q16)$", "imagemagick"),
        (r"^(cups|cups-daemon)$", "cups"),
        (r"^exim4-daemon-light$", "exim"),
        (r"^openvpn$", "openvpn"),
    ]
]

# Пакеты, которые не сопоставляются, и почему (причина показывается в ответе API).
NOT_COMPARED: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^linux-(image|modules|headers)-"),
     "ядро Linux не сопоставляется: дистрибутив переносит в ядро тысячи исправлений из новых версий, "
     "не меняя базовый номер (6.8.0), поэтому сравнение с диапазонами БДУ дало бы тысячи ложных находок; "
     "уязвимости ядра проверяются по бюллетеням дистрибутива"),
    (re.compile(r"^firefox$"), "в Ubuntu 24.04 пакет firefox — заглушка для snap, его версия не версия браузера"),
]


def not_compared_reason(package: str) -> str | None:
    name = package.strip().lower()
    for pattern, reason in NOT_COMPARED:
        if pattern.search(name):
            return reason
    return None


def product_for_package(package: str) -> str | None:
    name = package.strip().lower()
    if not_compared_reason(name):
        return None
    for pattern, product in ALIASES:
        if pattern.search(name):
            return product
    return name  # совпадение с продуктом БДУ целиком проверяет вызывающий код
