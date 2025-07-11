# Food-Ordering-System
 Enhancing Dining Experiences: An In-Depth Analysis of Online Food Ordering Systems and Their  Influence on Consumer Behavior




 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>
 #include <unistd.h>
 #define MAX_USERS 100
 1
#define MAX_ITEMS 10
 struct User {
 char username[30];
 char password[30];
 };
 struct MenuItem {
 char name[30];
 float price;
 };
 struct Order {
 char username[30];
 int item_ids[MAX_ITEMS];
 int quantities[MAX_ITEMS];
 int item_count;
 int status; // 0: confirmed, 1: processing, 2: delivered
 };
 struct User users[MAX_USERS];
 int user_count = 0;
 struct MenuItem menu[2] = { {"Pizza", 10.0}, {"Burger", 5.0} };
 struct Order orders[MAX_USERS];
 int order_count = 0;
 int authenticate(char* username, char* password) {
 for (int i = 0; i < user_count; i++) {
 if (strcmp(users[i].username, username) == 0 &&
 strcmp(users[i].password, password) == 0)
 return 1;
 }
 return 0;
 }
 void register_user() {
 printf("Enter username: ");
 scanf("%s", users[user_count].username);
 printf("Enter password: ");
 scanf("%s", users[user_count].password);
 user_count++;
 printf("User registered successfully.\n");
 }
 void display_menu() {
 printf("Menu:\n");
 for (int i = 0; i < 2; i++)
 printf("%d. %s: $%.2f\n", i+1, menu[i].name, menu[i].price);
 }
 void place_order(char* username) {
 2
struct Order o;
 strcpy(o.username, username);
 printf("Enter number of items: ");
 scanf("%d", &o.item_count);
 for (int i = 0; i < o.item_count; i++) {
 display_menu();
 int choice;
 printf("Enter item choice: ");
 scanf("%d", &choice);
 o.item_ids[i] = choice-1;
 printf("Enter quantity: ");
 scanf("%d", &o.quantities[i]);
 }
 o.status = 0;
 orders[order_count++] = o;
 printf("Order placed successfully.\n");
 }
 void track_order(char* username) {
 for (int i = 0; i < order_count; i++) {
 if (strcmp(orders[i].username, username) == 0) {
 if (orders[i].status == 0) printf("Order is confirmed.\n");
 else if (orders[i].status == 1) printf("Order is in process.\n");
 else printf("Order is delivered.\n");
 return;
 }
 }
 printf("No orders found.\n");
 }
 void process_delivery() {
 for (int i = 0; i < order_count; i++) {
 if (orders[i].status < 2) {
 printf("Delivering order to %s...\n", orders[i].username);
 sleep(2);
 orders[i].status++;
 if (orders[i].status == 2)
 printf("Order delivered to %s.\n", orders[i].username);
 }
 }
 }
 int main() {
 int choice;
 char current_user[30];
 int logged_in = 0;
 while (1) {
 if (!logged_in) {
 printf("\n1. Register\n2. Login\n3. Exit\nEnter your choice: ");
 scanf("%d", &choice);
 3
if (choice == 1) register_user();
 else if (choice == 2) {
 char username[30], password[30];
 printf("Enter username: "); scanf("%s", username);
 printf("Enter password: "); scanf("%s", password);
 if (authenticate(username, password)) {
 printf("Login successful.\n");
 strcpy(current_user, username);
 logged_in = 1;
 } else printf("Login failed.\n");
 }
 else break;
 } else {
 printf("\n1. Display Menu\n2. Place Order\n3. Track Order\n4. 
Process Delivery\n5. Logout\nEnter your choice: ");
 scanf("%d", &choice);
 if (choice == 1) display_menu();
 else if (choice == 2) place_order(current_user);
 else if (choice == 3) track_order(current_user);
 else if (choice == 4) process_delivery();
 else if (choice == 5) logged_in = 0;
 else break;
 }
 }
 printf("Exiting...\n");
 return 0;
 }
