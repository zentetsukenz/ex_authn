defmodule ExAuthn.RegisterFactory do
  use ExMachina

  defmacro __using__(_opts) do
    quote do
      def user_args_factory do
        %{
          id: <<sequence(:byte_1, & &1), sequence(:byte_2, &(&1 + 1))>>,
          name: sequence("Name"),
          display_name: sequence("Display Name"),
          icon: ""
        }
      end
    end
  end
end
