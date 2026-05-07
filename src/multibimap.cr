class MultiBiMap(L, R)
  @left_to_right : Hash(L, Set(R))
  @right_to_left : Hash(R, Set(L))

  def initialize
    @left_to_right = Hash(L, Set(R)).new { |h, k| h[k] = Set(R).new }
    @right_to_left = Hash(R, Set(L)).new { |h, k| h[k] = Set(L).new }
  end

  def add(left : L, right : R)
    @left_to_right[left] << right
    @right_to_left[right] << left
  end

  def remove_entry(left : L, right : R)
    @left_to_right[left].delete(right)
    @right_to_left[right].delete(left)
  end

  def delete_left(left : L)
    if rights = @left_to_right.delete(left)
      rights.each { |r| @right_to_left[r].delete(left) }
    end
  end

  def delete_right(right : R)
    if lefts = @right_to_left.delete(right)
      lefts.each { |l| @left_to_right[l].delete(right) }
    end
  end

  def for_left(left : L) : Set(R)
    @left_to_right[left]? || Set(R).new
  end

  def for_right(right : R) : Set(L)
    @right_to_left[right]? || Set(L).new
  end
end
