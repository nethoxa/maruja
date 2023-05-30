#!/bin/bash
if ! ls /dev/maruja | grep -q maruja; then
  printf "No hay maruja en el directorio /dev, cerrando...\n"
  exit 0
fi

cat /dev/maruja
sudo dmesg | tail