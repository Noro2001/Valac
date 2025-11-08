"""
CSV Extractor Module - Extracts domains from CSV files
"""

import csv
from urllib.parse import urlparse
from tqdm import tqdm

# Color codes
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"


class CSVExtractorModule:
    def extract_domain_from_url(self, url):
        """Extract domain from URL"""
        if not url or not isinstance(url, str):
            return None

        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if domain.startswith('www.'):
                domain = domain[4:]
            return domain if domain else None
        except (AttributeError, ValueError):
            return None

    def extract_domain_from_email(self, email):
        """Extract domain from email address"""
        if not email or not isinstance(email, str) or '@' not in email:
            return None

        try:
            domain = email.split('@')[1].lower()
            return domain
        except (IndexError, AttributeError):
            return None

    def extract_domains_from_csv(self, input_file, output_file, columns_to_check=None):
        import os
        domains = set()
        
        if not os.path.exists(input_file):
            print(f"{RED}[ERROR]{RESET} Input file not found: {input_file}")
            return

        try:
            with open(input_file, 'r', encoding='utf-8', newline='') as csvfile:
                sample = csvfile.read(1024)
                csvfile.seek(0)
                delimiter = ','
                if sample.count(';') > sample.count(','):
                    delimiter = ';'
                elif sample.count('\t') > sample.count(','):
                    delimiter = '\t'

                reader = csv.reader(csvfile, delimiter=delimiter)
                try:
                    headers = next(reader)
                except StopIteration:
                    print(f"{RED}[ERROR]{RESET} CSV file is empty or has no headers")
                    return

                print(f"{YELLOW}[INFO]{RESET} Found columns: {headers}")

                if columns_to_check is None:
                    columns_to_check = list(range(len(headers)))
                else:
                    column_indices = []
                    for col in columns_to_check:
                        if isinstance(col, str):
                            try:
                                column_indices.append(headers.index(col))
                            except ValueError:
                                print(f"{YELLOW}[WARN]{RESET} Column '{col}' not found")
                        else:
                            column_indices.append(col)
                    columns_to_check = column_indices

                # Count total rows first for progress bar
                rows = list(reader)
                total_rows = len(rows)
                
                if total_rows == 0:
                    print(f"{YELLOW}[WARN]{RESET} CSV file has no data rows")
                    return
                
                pbar = tqdm(
                    total=total_rows,
                    desc=f"{YELLOW}[EXTRACT]{RESET} Processing CSV",
                    unit="row",
                    bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]',
                    colour='green'
                )
                
                row_count = 0
                for row in rows:
                    row_count += 1

                    for col_idx in columns_to_check:
                        if col_idx < len(row):
                            cell_value = row[col_idx].strip()

                            if cell_value:
                                domain = self.extract_domain_from_url(cell_value)
                                if domain:
                                    domains.add(domain)

                                domain = self.extract_domain_from_email(cell_value)
                                if domain:
                                    domains.add(domain)
                    
                    pbar.update(1)
                    pbar.set_postfix({
                        'Domains': len(domains),
                        'Rows': row_count
                    })
                
                pbar.close()
                print(f"{GREEN}[INFO]{RESET} Processed {row_count} rows")

        except FileNotFoundError:
            print(f"{RED}[ERROR]{RESET} File '{input_file}' not found")
            return
        except Exception as e:
            print(f"{RED}[ERROR]{RESET} Error reading CSV: {e}")
            return

        if domains:
            try:
                with open(output_file, 'w', encoding='utf-8') as outfile:
                    for domain in sorted(domains):
                        outfile.write(domain + '\n')

                print(f"{GREEN}[SUCCESS]{RESET} Extracted {len(domains)} unique domains")
                print(f"{GREEN}[INFO]{RESET} Domains saved to: {output_file}")

                print(f"\n{YELLOW}First 10 domains:{RESET}")
                for i, domain in enumerate(sorted(domains)):
                    if i >= 10:
                        break
                    print(f"  {domain}")

            except Exception as e:
                print(f"{RED}[ERROR]{RESET} Error writing output file: {e}")
        else:
            print(f"{YELLOW}[WARN]{RESET} No domains found in the CSV file")

    def run(self, args):
        columns = args.columns if hasattr(args, 'columns') and args.columns else None
        self.extract_domains_from_csv(args.input, args.output, columns)

