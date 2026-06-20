import os
import json
import hashlib
import time
from scapy.utils import RawPcapReader

# =====================================================================
# POIN 3: STRUKTUR & KOMPONEN BLOCKCHAIN
# =====================================================================
class Block:
    def __init__(self, index, timestamp, evidence_file, packet_count, file_size, evidence_hash, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.evidence_file = evidence_file
        self.packet_count = packet_count
        self.file_size = file_size
        self.evidence_hash = evidence_hash
        self.previous_hash = previous_hash
        self.block_hash = self.calculate_block_hash()

    def to_dict(self):
        """Mengubah atribut blok menjadi dictionary untuk kalkulasi hash."""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "evidence_file": self.evidence_file,
            "packet_count": self.packet_count,
            "file_size": self.file_size,
            "evidence_hash": self.evidence_hash,
            "previous_hash": self.previous_hash
        }

    def calculate_block_hash(self):
        """Menghitung hash dari seluruh atribut blok (SHA-256)."""
        block_string = json.dumps(self.to_dict(), sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()


class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        """Membuat Genesis Block (Blok Awal/Indeks 0)."""
        genesis_block = Block(
            index=0,
            timestamp=time.time(),
            evidence_file="Genesis Block",
            packet_count=0,
            file_size=0,
            evidence_hash="0" * 64,
            previous_hash="0" * 64
        )
        self.chain.append(genesis_block)

    def get_latest_block(self):
        return self.chain[-1]

    def add_evidence_block(self, evidence_file, packet_count, file_size, evidence_hash):
        """Menambahkan Evidence Block baru ke dalam rantai."""
        latest_block = self.get_latest_block()
        new_block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            evidence_file=evidence_file,
            packet_count=packet_count,
            file_size=file_size,
            evidence_hash=evidence_hash,
            previous_hash=latest_block.block_hash # Menghubungkan rantai lewat hash blok sebelumnya
        )
        self.chain.append(new_block)

    # =====================================================================
    # POIN 4: MEKANISME VALIDASI BLOCKCHAIN
    # =====================================================================
    def validate_blockchain(self):
        """Memverifikasi kesesuaian previous hash, block hash, dan integritas rantai."""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            # 1. Validasi kesesuaian Block Hash internal
            if current_block.block_hash != current_block.calculate_block_hash():
                return "Blockchain Validation : INVALID"

            # 2. Validasi kesesuaian Previous Hash dengan Hash blok terdahulu
            if current_block.previous_hash != previous_block.block_hash:
                return "Blockchain Validation : INVALID"

        return "Blockchain Validation : VALID"

    def display_chain(self):
        """Mencetak struktur blockchain ke layar."""
        for block in self.chain:
            print("=" * 60)
            print(f"Index         : {block.index}")
            print(f"Timestamp     : {time.ctime(block.timestamp)}")
            print(f"Evidence File : {block.evidence_file}")
            print(f"Packet Count  : {block.packet_count} paket")
            print(f"File Size     : {block.file_size} bytes")
            print(f"Evidence Hash : {block.evidence_hash}")
            print(f"Previous Hash : {block.previous_hash}")
            print(f"Block Hash    : {block.block_hash}")
        print("=" * 60)


# =====================================================================
# POIN 2: FUNGSI FORENSIK (PACKET COUNT & HASHING SHA-256)
# =====================================================================
def get_pcap_packet_count(filepath):
    """Menghitung jumlah paket asli di dalam file PCAP."""
    count = 0
    try:
        for _ in RawPcapReader(filepath):
            count += 1
    except Exception as e:
        print(f"Gagal membaca paket pada file {filepath}: {e}")
    return count

def calculate_sha256(filepath):
    """Menghitung nilai hash SHA-256 dari file bukti digital."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


# =====================================================================
# ALUR UTAMA EKSEKUSI PROGRAM
# =====================================================================
if __name__ == "__main__":
    # 1. Inisialisasi Rantai Blockchain Baru
    pcap_blockchain = Blockchain()
    
    # 2. Setup path folder pencarian file pcap (relatif terhadap folder eksekusi)
    evidence_dir = os.path.join("..", "evidence")
    if not os.path.exists(evidence_dir):
        evidence_dir = "evidence" # fallback jika dijalankan langsung dari root project

    # Daftar file bukti digital (Silakan ubah 'NIM' sesuai NIM Anda)
    pcap_files = [
        "PCAP01_23040700092.pcap",
        "PCAP02_23040700092.pcap",
        "PCAP03_23040700092.pcap",
        "PCAP04_23040700092.pcap",
        "PCAP05_23040700092.pcap"
    ]

    pcap_metadata_list = []

    print("\n[PROSES POIN 2] Menghitung Metadata & Nilai Hash SHA-256 Bukti Digital:")
    for file_name in pcap_files:
        file_path = os.path.join(evidence_dir, file_name)
        
        if os.path.exists(file_path):
            size = os.path.getsize(file_path)
            packets = get_pcap_packet_count(file_path)
            file_hash = calculate_sha256(file_path)
            
            pcap_metadata_list.append({
                "name": file_name,
                "packets": packets,
                "size": size,
                "hash": file_hash
            })
            
            print("-" * 50)
            print(f"Nama File   : {file_name}")
            print(f"Jumlah Paket: {packets} paket")
            print(f"Ukuran File : {size} bytes")
            print(f"SHA-256 Hash: {file_hash}")
        else:
            print(f"[!] File {file_name} tidak ditemukan di folder '{evidence_dir}'")


    print("\n[PROSES POIN 3] Memasukkan Informasi Bukti ke Dalam Rantai Blockchain...")
    for meta in pcap_metadata_list:
        pcap_blockchain.add_evidence_block(
            evidence_file=meta["name"],
            packet_count=meta["packets"],
            file_size=meta["size"],
            evidence_hash=meta["hash"]
        )
    
    # Cetak visualisasi isi rantai ke terminal
    pcap_blockchain.display_chain()
    

    print("\n[PROSES POIN 4] Menjalankan Fungsi Validasi Integritas Blockchain:")
    status_validasi = pcap_blockchain.validate_blockchain()
    print(status_validasi)
    
    