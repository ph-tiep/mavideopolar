function E = entropy_calc(data)
p = histcounts(double(data(:)), 0:256) / numel(data);
p = p(p > 0);
E = -sum(p .* log2(p));
end
