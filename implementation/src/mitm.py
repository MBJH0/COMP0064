import threading

from .entities.attacker import Attacker
from .entities.vehicle import Vehicle


def run(address1: (str, int), address2: (str, int), debug: bool):
    vehicle_a = Vehicle(debug_mode=debug)
    vehicle_b = Vehicle(debug_mode=debug)
    attacker = Attacker(debug_mode=debug)
    vehicle_a_t = threading.Thread(target=vehicle_a_actions, args=[vehicle_a, address1])
    vehicle_a_t.start()
    attacker_t = threading.Thread(target=attacker_actions, args=[attacker, vehicle_a, vehicle_b, address1, address2])
    attacker_t.start()
    vehicle_b_t = threading.Thread(target=vehicle_b_actions, args=[vehicle_b, address2])
    vehicle_b_t.start()
    vehicle_a_t.join()
    attacker_t.join()
    vehicle_b_t.join()


def vehicle_a_actions(vehicle: Vehicle, address: (str, int)):
    vehicle.listen(address=address)
    vehicle.recv_message()


def vehicle_b_actions(vehicle: Vehicle, address: (str, int)):
    vehicle.connect(address=address)
    vehicle.send_message("This is a message sent by Vehicle B to Vehicle A")


def attacker_actions(attacker: Attacker, vehicle_a: Vehicle, vehicle_b: Vehicle, address1: (str, int), address2: (str, int)):
    attacker.intrude(listen_addr=address2, connect_addr=address1)
    attacker.eavesdrop(vehicle_a, vehicle_b)
