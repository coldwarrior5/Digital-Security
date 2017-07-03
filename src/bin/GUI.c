#include "allInclusions.h"

#define GUI_FILE "../miscelaneous/design.ui"
#define WIDGET_WINDOW "main"

int GUIMode(int argc, char *argv[])
{
  InitializeWindow(argc, argv);
  return 0;
}

void InitializeWindow(int argc, char *argv[])
{
  GtkWidget *window;
  GtkBuilder *builder;
  /* Initialize gtk+*/
  gtk_init(&argc, &argv);

  builder = gtk_builder_new ();
  gtk_builder_add_from_file(builder, GUI_FILE, NULL);

  window = GTK_WIDGET(gtk_builder_get_object (builder, WIDGET_WINDOW));
  gtk_builder_connect_signals(builder, NULL);

  gtk_widget_show(window);

  gtk_main ();
}