#include <stdio.h>
#include <unistd.h>

int x;

void f4(int a) {
    if (a) {
        f4(a - 1);
    }
}

void f3() {
    f4(5);
}
void f2() {
    f3();
}

void f1() {
    f2();
}

void do_print() {
    printf("Hello world!\n");
    sleep(1);
    f1();
}

int main()
{
    x = 10;
    for (int i = 0; i < 10; i++) {
        do_print();
    }
    for (int i = 0; i < 5; i++) {
        x += x;
    }
    return 0;
}
