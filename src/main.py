import loader
import exporter


def main():
    dataset = loader.load_dataset()
    dataset = loader.clean_data(dataset)

    exporter.export_analysis(dataset)


if __name__ == "__main__":
    main()
