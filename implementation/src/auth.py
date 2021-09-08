import threading

from .entities.vehicle import Vehicle


def run(address: (str, int), debug: bool):
    vehicle_a = Vehicle(debug_mode=debug)
    vehicle_b = Vehicle(debug_mode=debug)
    vehicle_a_t = threading.Thread(target=vehicle_a_actions, args=[vehicle_a, address])
    vehicle_a_t.start()
    vehicle_b_t = threading.Thread(target=vehicle_b_actions, args=[vehicle_b, address])
    vehicle_b_t.start()
    vehicle_a_t.join()
    vehicle_b_t.join()


def vehicle_a_actions(vehicle: Vehicle, address: (str, int)):
    vehicle.listen(address=address)
    vehicle.recv_message()
    vehicle.send_message("This is a response sent by Vehicle B to Vehicle A\n")


def vehicle_b_actions(vehicle: Vehicle, address: (str, int)):
    vehicle.connect(address=address)
    vehicle.send_message("This is a message sent by Vehicle A to Vehicle B\n")
    vehicle.recv_message()
