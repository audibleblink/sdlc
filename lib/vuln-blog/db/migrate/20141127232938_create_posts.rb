class CreatePosts < ActiveRecord::Migration[5.1]
  def change
    create_table :posts do |f|
      f.belongs_to :user

      f.string :title
      f.string :img
      f.text :body

      f.timestamps
    end
  end
end
