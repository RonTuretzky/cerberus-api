.PHONY: generate
generate:
	@echo "Generating..."
	cd proto && buf generate
	@echo "Done"