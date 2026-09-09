import os
import shutil
from pathlib import Path


class CertFactory:

    def __init__(self, cmd, output_dir):
        self.cmd = cmd
        self.dir = Path(output_dir)
        self.dir.mkdir(parents=True, exist_ok=True)

    def path(self, name):
        return self.dir / name

    @staticmethod
    def _algo_flags(algo, size=None, curve=None):
        args = ["-a", algo]
        if algo == "rsa" and size:
            args += ["-s", str(size)]
        elif algo == "ecdsa" and curve:
            args += ["--curve", curve]
        return args

    # --- certdiag-based generation ---

    def create_ca(self, name, subject, algo="rsa", size=4096, curve=None,
                  days=3650, sign_ca=None, sign_key=None, path_length=None):
        cert, key = self.path(f"{name}.pem"), self.path(f"{name}.key")
        args = ["create-cert", "--with-key"]
        args += self._algo_flags(algo, size, curve)
        args += ["--subject", subject, "--ca", "--days", str(days)]
        if path_length is not None:
            args += ["--path-length", str(path_length)]
        if sign_ca and sign_key:
            args += ["--sign-ca", str(sign_ca), "--sign-key", str(sign_key)]
        args += ["-o", str(cert), "--key-output", str(key), "--no-confirm"]
        self.cmd.run(*args, check=True)
        return cert, key

    def create_cert(self, name, subject, algo="rsa", size=2048, curve=None,
                    days=365, san=None, sign_ca=None, sign_key=None,
                    extra_args=None):
        cert, key = self.path(f"{name}.pem"), self.path(f"{name}.key")
        args = ["create-cert", "--with-key"]
        args += self._algo_flags(algo, size, curve)
        args += ["--subject", subject, "--days", str(days)]
        if san:
            args += ["--san", san]
        if sign_ca and sign_key:
            args += ["--sign-ca", str(sign_ca), "--sign-key", str(sign_key)]
        if extra_args:
            args += extra_args
        args += ["-o", str(cert), "--key-output", str(key), "--no-confirm"]
        self.cmd.run(*args, check=True)
        return cert, key

    def create_key(self, name, algo="rsa", size=2048, curve=None, fmt="pem",
                   encrypt=False, password=None):
        key = self.path(name)
        args = ["create-key"]
        args += self._algo_flags(algo, size, curve)
        if fmt != "pem":
            args += ["-f", fmt]
        if encrypt and password:
            args += ["--encrypt-key", "-p", password]
        args += ["-o", str(key), "--no-confirm"]
        self.cmd.run(*args, check=True)
        return key

    def create_csr(self, name, subject, algo="ed25519", san=None, fmt="pem"):
        csr = self.path(name)
        args = ["csr", "--with-key", "-a", algo, "--subject", subject]
        if san:
            args += ["--san", san]
        if fmt != "pem":
            args += ["-f", fmt]
        args += ["-o", str(csr), "--no-confirm"]
        self.cmd.run(*args, check=True)
        return csr

    def convert(self, src, dst_name, fmt, password=None, output_password=None):
        dst = self.path(dst_name)
        args = ["convert", str(src), "-f", fmt, "-o", str(dst), "--no-confirm"]
        if password:
            args += ["-p", password]
        if output_password:
            args += ["--output-password", output_password]
        self.cmd.run(*args, check=True)
        return dst

    def bundle(self, files, dst_name, fmt="pem", password=None,
               alias=None, legacy=False):
        dst = self.path(dst_name)
        args = ["bundle"] + [str(f) for f in files]
        args += ["-f", fmt, "-o", str(dst), "--no-confirm"]
        if password:
            args += ["--output-password", password]
        if alias:
            args += ["--alias", alias]
        if legacy:
            args += ["--legacy-pkcs12"]
        self.cmd.run(*args, check=True)
        return dst

    # --- openssl-based generation ---

    def openssl_selfsigned(self, name, algo="rsa2048", subject="CN=Test", days=3650):
        cert, key = self.path(f"{name}.crt"), self.path(f"{name}.key")
        algo_args = {
            "rsa2048": ["-newkey", "rsa:2048"],
            "rsa4096": ["-newkey", "rsa:4096"],
            "ecp256":  ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"],
            "ecp384":  ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-384"],
        }
        args = ["openssl", "req", "-x509"]
        args += algo_args.get(algo, ["-newkey", algo])
        args += ["-keyout", str(key), "-out", str(cert),
                 "-days", str(days), "-noenc", "-subj", f"/{subject}"]
        self.cmd.tool(*args, check=True)
        return cert, key

    def openssl_pkcs12(self, name, cert, key, password, chain=None,
                       iterations=None, legacy=False, alias=None):
        dst = self.path(name)
        args = ["openssl", "pkcs12", "-export",
                "-in", str(cert), "-inkey", str(key),
                "-out", str(dst), "-passout", f"pass:{password}"]
        if chain:
            args += ["-certfile", str(chain)]
        if iterations:
            args += ["-iter", str(iterations)]
        if alias:
            args += ["-name", alias]
        if legacy:
            args += ["-certpbe", "PBE-SHA1-3DES", "-keypbe", "PBE-SHA1-3DES", "-macalg", "sha1"]
        self.cmd.tool(*args, check=True)
        return dst

    def openssl_pkcs8(self, src_key, dst_name, password, iterations=None):
        dst = self.path(dst_name)
        args = ["openssl", "pkcs8", "-topk8",
                "-in", str(src_key), "-out", str(dst),
                "-v2", "aes-256-cbc", "-passout", f"pass:{password}"]
        if iterations:
            args += ["-iter", str(iterations)]
        self.cmd.tool(*args, check=True)
        return dst

    def keytool_genkeypair(self, keystore_name, alias, password, subject,
                           algo="RSA", keysize=2048, days=3650):
        dst = self.path(keystore_name)
        self.cmd.tool("keytool", "-genkeypair",
                      "-alias", alias, "-keyalg", algo, "-keysize", str(keysize),
                      "-validity", str(days), "-dname", subject,
                      "-keystore", str(dst), "-storetype", "JKS",
                      "-storepass", password, "-keypass", password, check=True)
        return dst

    def keytool_importcert(self, keystore, alias, cert_file, password):
        self.cmd.tool("keytool", "-importcert",
                      "-alias", alias, "-file", str(cert_file),
                      "-keystore", str(keystore), "-storetype", "JKS",
                      "-storepass", password, "-noprompt", check=True)

    def keytool_import_p12(self, p12_file, p12_password, keystore, ks_password):
        self.cmd.tool("keytool", "-importkeystore",
                      "-srckeystore", str(p12_file), "-srcstoretype", "PKCS12",
                      "-srcstorepass", p12_password, "-destkeystore", str(keystore),
                      "-deststoretype", "JKS", "-deststorepass", ks_password, "-noprompt",
                      check=True)

    # --- PEM / file manipulation ---

    def concat(self, dst_name, *src_files):
        dst = self.path(dst_name)
        parts = []
        for f in src_files:
            if isinstance(f, (str, Path)):
                parts.append(Path(f).read_text())
            else:
                parts.append(str(f))
        dst.write_text("".join(parts))
        return dst

    def copy(self, src, dst_name):
        dst = self.path(dst_name)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        return dst

    def write(self, name, content):
        dst = self.path(name)
        dst.write_text(content)
        return dst

    def write_bytes(self, name, data):
        dst = self.path(name)
        dst.write_bytes(data)
        return dst

    def touch(self, name):
        dst = self.path(name)
        dst.touch()
        return dst

    def random_bytes(self, name, size=1024):
        return self.write_bytes(name, os.urandom(size))

    def truncate(self, src, dst_name, byte_count):
        dst = self.path(dst_name)
        dst.write_bytes(Path(src).read_bytes()[:byte_count])
        return dst

    def crlf(self, src, dst_name):
        dst = self.path(dst_name)
        # write_text would re-translate \n -> \r\n on Windows, yielding \r\r\n.
        # Write bytes so the CRLF endings land exactly as intended.
        text = Path(src).read_text().replace("\n", "\r\n")
        dst.write_bytes(text.encode("utf-8"))
        return dst

    def mkdir(self, *parts):
        d = self.dir.joinpath(*parts)
        d.mkdir(parents=True, exist_ok=True)
        return d

    def fake_asn1(self, name, header_bytes, random_tail=60):
        data = bytes(header_bytes) + os.urandom(random_tail)
        return self.write_bytes(name, data)
