 
FROM archlinux:latest

WORKDIR tmp

RUN pacman -Syu --noconfirm && pacman -S --noconfirm base-devel cmake git sudo capnproto qt5-base qt5-quickcontrols quazip

RUN useradd newuser && passwd -d newuser

RUN printf 'newuser ALL=(ALL) ALL\n' | tee -a /etc/sudoers

RUN sudo -u newuser bash -c 'git clone https://aur.archlinux.org/redis-plus-plus.git rpp && cd rpp && makepkg -si --noconfirm'

USER root
    
RUN git clone https://github.com/pe200012/cpp-assignment.git cpp

WORKDIR cpp/build

RUN cmake .. && cmake --build .

RUN ./server
