export const NVIDIA_ARCHIVE = Object.freeze({
  "url": "https://developer.download.nvidia.com/compute/nvat/redist/libnvat/linux-sbsa/libnvat-linux-sbsa-1.2.2.1780962352-archive.tar.xz",
  "name": "libnvat-linux-sbsa-1.2.2.1780962352-archive.tar.xz",
  "size": 5407640,
  "sha256": "720455eb71d3aca50dc9fbd0900b0fa72fe36b6500fb5c5d453e7f4e9300187c"
});

export const GPU_DEPENDENCIES = [
  {
    "url": "https://ports.ubuntu.com/ubuntu-ports/pool/main/c/ca-certificates/ca-certificates_20260601%7e24.04.1_all.deb",
    "name": "ca-certificates_20260601~24.04.1_all.deb",
    "size": 139430,
    "sha512": "1b7219944f6aa70a8048d567c81683d82267bd9fddcdfd5e5962ca30432a5c8a7be71d21ee857b1a804956e7d23b1cea7c1a42e31d01df6513fc5313ada4a7e2",
    "sha256": "6bac2a01979e210d9eac1d4d56747ec709ea60654744d66705dc3c36e7629e50"
  },
  {
    "url": "https://ports.ubuntu.com/ubuntu-ports/pool/main/i/icu/libicu74_74.2-1ubuntu3.1_arm64.deb",
    "name": "libicu74_74.2-1ubuntu3.1_arm64.deb",
    "size": 10806898,
    "sha512": "6e06a4056fa98e6b14179f3e073d3c3774cb6570ae02829f411596cbba9c2b171b8f01def1c398d957f5d95028a40036b02c0e3de79aab3d0a748a5f49bcaa17",
    "sha256": "48f93acf50dcf237a8d58ce366730a28438ce52d3f06d7a2a88b51261dd791f7"
  },
  {
    "url": "https://ports.ubuntu.com/ubuntu-ports/pool/main/x/xz-utils/liblzma5_5.6.1%2breally5.4.5-1ubuntu0.3_arm64.deb",
    "name": "liblzma5_5.6.1+really5.4.5-1ubuntu0.3_arm64.deb",
    "size": 125976,
    "sha512": "3ea861b2a5b2943cbd32208f63ae22959183c693461939435d7ab382099365e63488d3009de9f71c3f1f4230ff80b4cb17686b29213a91eadd6ce59409524c21",
    "sha256": "2f58fd7de725efd0dbebe9d4442049fdacd7c2e8242f4288a13a688d50507245"
  },
  {
    "url": "https://ports.ubuntu.com/ubuntu-ports/pool/main/g/gcc-14/libstdc%2b%2b6_14.2.0-4ubuntu2%7e24.04.1_arm64.deb",
    "name": "libstdc++6_14.2.0-4ubuntu2~24.04.1_arm64.deb",
    "size": 750976,
    "sha512": "adb9cd460664489d542e3047811c3b9721901625bd09558aa7fef9b43f3bc225e83df0e329d12ff2d6d111d74b95efc793431b68a817e27d17b8c66826db32d1",
    "sha256": "f84a05ac45a6884109b6527e911081a38263b89e042fc94a338cf975f61a330c"
  },
  {
    "url": "https://ports.ubuntu.com/ubuntu-ports/pool/main/libx/libxml2/libxml2_2.9.14%2bdfsg-1.3ubuntu3.9_arm64.deb",
    "name": "libxml2_2.9.14+dfsg-1.3ubuntu3.9_arm64.deb",
    "size": 737396,
    "sha512": "1f66ae385addbac2b1358937a3234241605d8fb4807eac18cc0b0cd0f5f50318f6ccdb73efcb7f29372dbd748fac1c68c569486933a72c87cb82c62b5cdb22c9",
    "sha256": "dddfd368cf2e515d94b84a27ee3819a54ea6e208b0a34c7c2dc5948357e5cd83"
  }
] as const;

export const GPU_DOCKERFILE = "FROM ubuntu@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55\nARG SOURCE_DATE_EPOCH=0\nCOPY *.deb /deps/\nRUN for package in /deps/*.deb; do dpkg-deb -x \"$package\" /; done && mkdir -p /etc/ssl/certs && find /usr/share/ca-certificates -type f -name '*.crt' -print0 | sort -z | xargs -0 cat > /etc/ssl/certs/ca-certificates.crt && rm -rf /deps\nENV LD_LIBRARY_PATH=/evidence/libnvat-linux-sbsa-1.2.2.1780962352-archive/lib\nENTRYPOINT [\"/evidence/libnvat-linux-sbsa-1.2.2.1780962352-archive/bin/nvattest\"]\n";

export const GPU_IMAGE_ARCHIVE_SHA256 = "48d8202ed8b45bca8e1f8a7bdb189130d2e519ea1425744603cc9bfa41e7a1d0";
