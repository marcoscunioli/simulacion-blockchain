from __future__ import annotations

from dataclasses import dataclass, asdict
from hashlib import sha256
import json
from datetime import datetime, timezone
from uuid import uuid4
from typing import Dict, List, Tuple, Optional

from urllib.parse import urlparse  # (se deja por si luego querés usar registrar_nodo)
import streamlit as st
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from pymerkle import InmemoryTree as MerkleTree


# =========================
# Utilidades de hashing
# =========================
def _json_dumps(obj) -> str:
    # Serialización consistente
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sha256_hex(data: bytes) -> str:
    return sha256(data).hexdigest()


def hash_json(obj) -> str:
    return sha256_hex(_json_dumps(obj).encode("utf-8"))


# =========================
# Modelo de Nodos
# =========================
@dataclass
class Nodo:
    nombre: str
    direccion: str
    saldo: int = 0
    # Nota: si quisieras firmar transacciones, guarda también la clave aquí.


class Nodos:
    def __init__(self):
        self.nodos: Dict[str, Nodo] = {}
        nombres = [
            "Satoshi Nakamoto",
            "Niels Bohr",
            "Louis De Broglie",
            "Paul Dirac",
            "Albert Einstein",
            "Werner Heisenberg",
            "James Clerk Maxwell",
            "Isaac Newton",
            "Wolfgang Pauli",
            "Max Planck",
            "Erwin Schroedinger",
        ]
        for nombre in nombres:
            direccion = self._crear_direccion()
            self.nodos[direccion] = Nodo(nombre=nombre, direccion=direccion, saldo=0)
        # Faucet
        satoshi = next(n for n in self.nodos.values() if n.nombre == "Satoshi Nakamoto")
        satoshi.saldo = 1000

    def _crear_direccion(self) -> str:
        # Genera par de claves ECC (no se guarda priv en este demo)
        priv = ec.generate_private_key(ec.SECP384R1())
        pub = priv.public_key()
        pub_serial = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        h = sha256()
        h.update(pub_serial)
        return h.hexdigest()

    def to_table(self) -> List[dict]:
        return [asdict(n) for n in self.nodos.values()]


# =========================
# Blockchain
# =========================
class Blockchain:
    def __init__(self, dificultad: int = 4):
        self.cadena: List[dict] = []
        self.mempool: List[dict] = []
        self.dificultad: int = dificultad
        self._bloque_genesis()

    @property
    def ultimo_bloque(self) -> dict:
        return self.cadena[-1]

    # ---------- Bloque génesis ----------
    def _bloque_genesis(self):
        header = {
            "indice": 1,
            "hash_previo": "0" * 64,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "dificultad": self.dificultad,
            "merkle_root": "0" * 64,
            "nonce": 0,
        }
        bloque = {"header": header, "body": {"transacciones": [], "tx_count": 0}}
        self.cadena.append(bloque)

    # ---------- Merkle por BLOQUE ----------
    @staticmethod
    def merkle_root_de_txs(txs: List[dict]) -> str:
        tree = MerkleTree(algorithm="sha256")
        for tx in txs:
            tree.append_entry(_json_dumps(tx).encode("utf-8"))
        return tree.get_state().hex()

    # ---------- Hash del header ----------
    @staticmethod
    def hash_header(header: dict) -> str:
        return hash_json(header)

    # ---------- Validación de PoW ----------
    @staticmethod
    def cumple_dificultad(h: str, dificultad: int) -> bool:
        return h.startswith("0" * dificultad)

    # ---------- API pública ----------
    def agregar_tx(self, remitente: str, destinatario: str, monto: int, info: str) -> int:
        """Agrega a mempool. Los saldos se aplican al minar."""
        self.mempool.append(
            {
                "remitente": remitente,
                "destinatario": destinatario,
                "monto": int(monto),
                "info": info,
            }
        )
        return self.ultimo_bloque["header"]["indice"] + 1

    def minar_bloque(self, direccion_minero: str, nodos: Nodos) -> Tuple[dict, dict]:
        """
        Arma bloque: coinbase + mempool. Aplica transacciones válidas a saldos.
        Devuelve (bloque, stats) donde stats tiene contadores de tx aceptadas/rechazadas.
        """
        prev_header = self.ultimo_bloque["header"]
        hash_previo = self.hash_header(prev_header)

        # Coinbase primero
        txs_candidatas = [
            {
                "remitente": "COINBASE",
                "destinatario": direccion_minero,
                "monto": 1,
                "info": "Recompensa por minado",
            }
        ] + list(self.mempool)

        # Validar y aplicar saldos (contabilidad en minado)
        aceptadas: List[dict] = []
        rechazadas: List[dict] = []

        # Aplica coinbase directamente
        self._aplicar_tx(txs_candidatas[0], nodos, aceptar_sin_fondos=True)
        aceptadas.append(txs_candidatas[0])

        # Resto: validar fondos
        for tx in txs_candidatas[1:]:
            if self._tx_valida(tx, nodos):
                self._aplicar_tx(tx, nodos)
                aceptadas.append(tx)
            else:
                rechazadas.append(tx)

        txs_finales = aceptadas
        merkle_root = self.merkle_root_de_txs(txs_finales)

        header_base = {
            "indice": len(self.cadena) + 1,
            "hash_previo": hash_previo,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "dificultad": self.dificultad,
            "merkle_root": merkle_root,
        }

        # PoW sobre el header (incluye nonce)
        nonce = 0
        while True:
            header = {**header_base, "nonce": nonce}
            h = self.hash_header(header)
            if self.cumple_dificultad(h, self.dificultad):
                break
            nonce += 1

        bloque = {"header": header, "body": {"transacciones": txs_finales, "tx_count": len(txs_finales)}}
        self.cadena.append(bloque)
        self.mempool = []  # limpia mempool tras minar

        stats = {
            "aceptadas": len(aceptadas) - 1,  # sin contar coinbase
            "rechazadas": len(rechazadas),
            "hash_bloque": self.hash_header(bloque["header"]),
            "nonce": nonce,
        }
        return bloque, stats

    def validar_cadena(self) -> Tuple[bool, str]:
        """Verifica encadenamiento, Merkle, y dificultad/PoW."""
        if not self.cadena:
            return False, "Cadena vacía"

        for i in range(1, len(self.cadena)):
            actual = self.cadena[i]
            previo = self.cadena[i - 1]
            # Encadenamiento
            if actual["header"]["hash_previo"] != self.hash_header(previo["header"]):
                return False, f"Hash previo inválido en bloque #{actual['header']['indice']}"

            # Merkle
            recalculada = self.merkle_root_de_txs(actual["body"]["transacciones"])
            if recalculada != actual["header"]["merkle_root"]:
                return False, f"Merkle root inválida en bloque #{actual['header']['indice']}"

            # Dificultad / PoW
            h = self.hash_header(actual["header"])
            if not self.cumple_dificultad(h, actual["header"]["dificultad"]):
                return False, f"PoW inválida en bloque #{actual['header']['indice']}"

        return True, "Blockchain válida"

    # ---------- Helpers de saldos ----------
    @staticmethod
    def _tx_valida(tx: dict, nodos: Nodos) -> bool:
        if tx["monto"] <= 0:
            return False
        if tx["remitente"] == tx["destinatario"]:
            return False
        if tx["remitente"] == "COINBASE":
            return True
        remit = nodos.nodos.get(tx["remitente"])
        dest = nodos.nodos.get(tx["destinatario"])
        if not remit or not dest:
            return False
        return remit.saldo >= tx["monto"]

    @staticmethod
    def _aplicar_tx(tx: dict, nodos: Nodos, aceptar_sin_fondos: bool = False) -> None:
        """Modifica saldos. Para COINBASE aceptar_sin_fondos=True."""
        monto = int(tx["monto"])
        if tx["remitente"] != "COINBASE":
            remit = nodos.nodos.get(tx["remitente"])
            if not remit:
                return
            if not aceptar_sin_fondos and remit.saldo < monto:
                return
            remit.saldo -= monto
        dest = nodos.nodos.get(tx["destinatario"])
        if dest:
            dest.saldo += monto


# =========================
# App (Streamlit)
# =========================
st.set_page_config(page_title="Blockchain educativa", layout="wide")

@st.cache_resource
def setup():
    return Blockchain(dificultad=4), Nodos()

def _fmt_addr(addr: str) -> str:
    return addr[:12] + "…"

def _build_select_options(nodos: Nodos) -> Tuple[List[str], Dict[str, str]]:
    """
    Devuelve (labels, map_label_a_direccion)
    """
    labels = []
    mapping = {}
    for n in nodos.nodos.values():
        label = f"{n.nombre} | {_fmt_addr(n.direccion)}"
        labels.append(label)
        mapping[label] = n.direccion
    labels.sort()
    return labels, mapping

def main():
    blockchain, lista_nodos = setup()

    # Miner address persistente en sesión
    if "miner_addr" not in st.session_state:
        # por defecto, minero = primer nodo (Satoshi)
        st.session_state["miner_addr"] = next(iter(lista_nodos.nodos.keys()))
    if "miner_uuid" not in st.session_state:
        st.session_state["miner_uuid"] = str(uuid4()).replace("-", "")  # no se usa en contabilidad, se deja como id visual

    st.markdown("### **Marcos Cunioli** – *Especialista en Ciberseguridad*")
    st.title("Blockchain educativa (PoW + Merkle)")
    st.caption("Demo didáctica con mempool, PoW sobre header y Merkle por bloque")

    # ---------- Columna izquierda: cadena y validación ----------
    col1, col2 = st.columns([2, 1], gap="large")

    with col1:
        st.subheader("Blockchain")
        st.json({"longitud": len(blockchain.cadena), "blockchain": blockchain.cadena}, expanded=False)

        if st.button("Validar Blockchain"):
            ok, msg = blockchain.validar_cadena()
            (st.success if ok else st.error)(msg)

    # ---------- Columna derecha: balances, último bloque, merkle ----------
    with col2:
        st.subheader("Balances")
        tabla = [
            {"nombre": n.nombre, "direccion": _fmt_addr(n.direccion), "saldo": n.saldo}
            for n in lista_nodos.nodos.values()
        ]
        st.dataframe(tabla, use_container_width=True, hide_index=True)

        st.subheader("Último bloque")
        st.json(blockchain.ultimo_bloque, expanded=False)
        st.caption("Merkle root del último bloque")
        st.code(blockchain.ultimo_bloque["header"]["merkle_root"], language="text")

    # ---------- Sidebar ----------
    with st.sidebar:
        st.header("Operaciones")

        # ----- Transacciones -----
        st.subheader("Nueva transacción")
        labels, map_label_addr = _build_select_options(lista_nodos)

        with st.form("transaccion", clear_on_submit=True):
            remit_label = st.selectbox("Remitente", labels, index=0, key="remit_label")
            dest_label = st.selectbox("Destinatario", labels, index=1 if len(labels) > 1 else 0, key="dest_label")
            monto = st.number_input("Monto", min_value=1, step=1)
            boton_tx = st.form_submit_button("Agregar a mempool")

        if boton_tx:
            remitente = map_label_addr[remit_label]
            destinatario = map_label_addr[dest_label]
            if remitente == destinatario:
                st.warning("El remitente y el destinatario no pueden ser el mismo.")
            else:
                info = f"{lista_nodos.nodos[remitente].nombre} -> {lista_nodos.nodos[destinatario].nombre}"
                indice = blockchain.agregar_tx(remitente, destinatario, monto, info)
                st.toast(f"Transacción añadida a mempool. Estará en el bloque #{indice} si es válida al minar.")

        # ----- Minado -----
        st.subheader("Minar bloque")
        # Elegir minero entre nodos existentes
        minero_labels, minero_map = _build_select_options(lista_nodos)
        minero_pre = next(
            (label for label, addr in minero_map.items() if addr == st.session_state["miner_addr"]), minero_labels[0]
        )
        minero_label = st.selectbox("Minero", minero_labels, index=minero_labels.index(minero_pre))
        st.session_state["miner_addr"] = minero_map[minero_label]

        if st.button("Minar"):
            bloque, stats = blockchain.minar_bloque(st.session_state["miner_addr"], lista_nodos)
            st.toast("¡Nuevo bloque minado!")
            with st.expander("Detalles de minado"):
                st.write(
                    f"Tx aceptadas (sin coinbase): {stats['aceptadas']} | "
                    f"Tx rechazadas: {stats['rechazadas']} | "
                    f"Nonce: {stats['nonce']}"
                )
                st.code(stats["hash_bloque"], language="text")

        # ----- Varios -----
        st.subheader("Estado")
        st.write(f"Bloques: {len(blockchain.cadena)} | Dificultad: {blockchain.dificultad}")
        st.caption(f"Miner UUID (visual): {st.session_state['miner_uuid']}")

if __name__ == "__main__":
    main()
