#!/bin/bash
if ! ls | grep -q bin; then
  echo "No hay bin, compila con el run.sh"
  exit 0
fi
cd bin
if ! ls | grep -q maruja.ko; then
  echo "No hay maruja.ko, compila con el run.sh"
  exit 0
fi
printf "\nInstalando maruja...\n\n"
read -p "Tamaño del firewall (10 por defecto ) -> " tam
if [[ $tam -le 0 ]]; then
  echo "¿Qué haces pasando un tamaño negativo?"
  exit 0
fi

if [[ "$tam" == "" ]]; then
  sudo insmod maruja.ko
else
  sudo insmod maruja.ko fw_ip_count_max=$tam
fi
sudo dmesg | tail
read -p "Major de maruja -> " major
printf "\nCreando /dev/maruja y poniendo los permisos correctos...\n"
sudo mknod /dev/maruja c $major 0
sudo chmod 777 /dev/maruja
ls -l /dev/maruja
lsmod | grep maruja
cd ..
echo "maruja creado"